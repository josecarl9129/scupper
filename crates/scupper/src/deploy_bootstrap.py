import sys, json, os, stat, hashlib, gzip, io, tarfile, re
LIMIT = 512 * 1024 * 1024
def refuse():
    raise RuntimeError("invalid remote deploy request or archive")
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            refuse()
        result[key] = value
    return result
def directory(path, create=False):
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
    m = os.lstat(path)
    if not stat.S_ISDIR(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022:
        refuse()
def regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        m = os.fstat(f.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022 or m.st_size > LIMIT + 65536:
            refuse()
        data = f.read(LIMIT + 65537)
        if len(data) > LIMIT + 65536:
            refuse()
        return data
def write(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
try:
    raw = sys.stdin.buffer.read(1048577)
    if len(raw) > 1048576:
        refuse()
    req = json.loads(raw, object_pairs_hook=unique)
    if set(req) != {"op", "args", "request_id"}:
        refuse()
    valid_id = lambda x: isinstance(x, str) and re.fullmatch("[a-z0-9][a-z0-9-]{0,31}", x)
    if not valid_id(req["request_id"]):
        refuse()
    op, args = req["op"], req["args"]
    if op not in ("Prepare", "Stage") or not isinstance(args, dict) or set(args) != ({"id"} if op == "Prepare" else {"id", "sha256"}) or not valid_id(args["id"]):
        refuse()
    if op == "Stage" and not (isinstance(args["sha256"], str) and re.fullmatch("[a-f0-9]{64}", args["sha256"])):
        refuse()
    base = "/usr/local/lib/scupper/deploy"
    for path in ("/", "/usr", "/usr/local", "/usr/local/lib"):
        directory(path)
    directory("/usr/local/lib/scupper", op == "Prepare")
    directory(base, op == "Prepare")
    stage = base + "/" + args["id"]
    if op == "Prepare":
        os.mkdir(stage, 0o700)
        os.mkdir(stage + "/new", 0o700)
        print("fresh")
    else:
        directory(stage)
        stage += "/new"
        directory(stage)
        archive = regular(stage + "/archive.tar.gz")
        if hashlib.sha256(archive).hexdigest() != args["sha256"]:
            refuse()
        with gzip.GzipFile(fileobj=io.BytesIO(archive)) as f:
            tar = f.read(LIMIT + 1)
        if len(tar) > LIMIT:
            refuse()
        members = {}
        allowed = {"MANIFEST", "scupper", "scupperd", "scupper-net.service", "scupperd.service"}
        with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as f:
            for m in f:
                if m.name not in allowed or m.name in members or not m.isfile() or m.size > LIMIT or m.pax_headers:
                    refuse()
                members[m.name] = f.extractfile(m).read()
        if set(members) != allowed:
            refuse()
        manifest = "".join(hashlib.sha256(members[n]).hexdigest() + "  " + n + "\n" for n in sorted(allowed - {"MANIFEST"})).encode()
        if members["MANIFEST"] != manifest:
            refuse()
        write(stage + "/SHA256SUMS", (args["sha256"] + "  archive.tar.gz\n").encode(), 0o644)
        for name, data in sorted(members.items()):
            write(stage + "/" + name, data, 0o755 if name in ("scupper", "scupperd") else 0o644)
        print("Archive and MANIFEST verified.")
except Exception:
    print("remote deploy refused", file=sys.stderr)
    sys.exit(1)
