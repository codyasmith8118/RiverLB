"""Bounded PCAP output for a private helper-created job directory.

No socket, command or public endpoint is opened by this module. The worker must
supply a deadline-bounded receiver and independently trusted policy inventory.
"""
import errno
import os
import stat
import struct
import time


PCAP_HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 96, 1)
MAX_PACKETS = 200000


def write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError(errno.ENOSPC, 'Capture output unavailable')
        view = view[count:]


def write(directory, request, receive, select_headers, stopped,
          clock=time.monotonic, wall=time.time, owner_uid=0):
    """Produce a valid bounded file, or remove our incomplete file on failure.

    The receiver must return within a short poll interval, and return bytes or
    None. It may raise StopIteration when a synthetic/test source is exhausted.
    Neither a late receiver nor cancellation permits a record after the deadline.
    The helper never accepts directory, receiver, clocks or owner UID over RPC.
    """
    if (type(request.duration_seconds) is not int or not 1 <= request.duration_seconds <= 60
            or type(request.max_bytes) is not int or not 4096 <= request.max_bytes <= 16*1024*1024):
        raise ValueError("Invalid capture resource limit")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(directory, flags)
    fd = None
    created = False
    try:
        info = os.fstat(parent)
        if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Unsafe capture directory')
        fd = os.open('capture.pcap', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        created = True
        os.fchmod(fd, 0o600)
        if os.fstat(fd).st_uid != owner_uid:
            raise ValueError('Unsafe capture file owner')
        write_all(fd, PCAP_HEADER)
        size, packets, observed = len(PCAP_HEADER), 0, 0
        deadline = clock() + request.duration_seconds
        while True:
            if stopped():
                reason = 'canceled'
                break
            if clock() >= deadline:
                reason = 'time_limit'
                break
            if observed >= MAX_PACKETS:
                reason = 'packet_limit'
                break
            try:
                frame = receive(deadline)
            except StopIteration:
                reason = 'source_closed'
                break
            if stopped():
                reason = 'canceled'
                break
            if clock() >= deadline:
                reason = 'time_limit'
                break
            if frame is None:
                continue
            observed += 1
            headers = select_headers(frame)
            if headers is None:
                continue
            if type(headers) is not bytes or not 14 <= len(headers) <= 96 or not frame.startswith(headers):
                raise ValueError('Invalid capture header extraction')
            timestamp = wall()
            seconds = int(timestamp)
            record = struct.pack('<IIII', seconds, int((timestamp-seconds)*1000000),
                                 len(headers), len(frame)) + headers
            if size + len(record) > request.max_bytes:
                reason = 'byte_limit'
                break
            write_all(fd, record)
            size += len(record)
            packets += 1
        os.fsync(fd)
        closing, fd = fd, None
        os.close(closing)
        os.fsync(parent)
        return dict(reason=reason, bytes=size, packets=packets, observed=observed)
    except BaseException:
        if fd is not None:
            os.close(fd)
            fd = None
        if created:
            os.unlink('capture.pcap', dir_fd=parent)
        raise
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
