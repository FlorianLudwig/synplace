import sys
import os
import socket
from socket import AF_UNIX, SOCK_STREAM
import time
import errno
from struct import pack, unpack, Struct
import logging as log
from functools import partial

from eunuchs.socketpair import socketpair
from sendmsg import recvmsg, SCM_RIGHTS

import tornado
from tornado import iostream, ioloop

log.basicConfig(level=log.DEBUG)

in_format = Struct('=IIQQIII')
out_format = Struct('=IiQ')

FUSE_KERNEL_VERSION = 7
FUSE_KERNEL_MINOR_VERSION = 5

FUSE_LOOKUP = 1
FUSE_FORGET = 2
FUSE_GETATTR = 3
FUSE_SETATTR = 4
FUSE_READLINK = 5
FUSE_SYMLINK = 6
FUSE_MKNOD = 8
FUSE_MKDIR = 9
FUSE_UNLINK = 10
FUSE_RMDIR = 11
FUSE_RENAME = 12
FUSE_LINK = 13
FUSE_OPEN = 14
FUSE_READ = 15
FUSE_WRITE = 16
FUSE_STATFS = 17
FUSE_RELEASE = 18
FUSE_FSYNC = 20
FUSE_SETXATTR = 21
FUSE_GETXATTR = 22
FUSE_LISTXATTR = 23
FUSE_REMOVEXATTR = 24
FUSE_FLUSH = 25
FUSE_INIT = 26
FUSE_OPENDIR = 27
FUSE_READDIR = 28
FUSE_RELEASEDIR = 29

dispatch = {FUSE_LOOKUP: 'lookup',
            FUSE_FORGET: 'forget',
            FUSE_GETATTR: 'getattr',
            FUSE_OPEN: 'open',
            FUSE_READ: 'read',
            FUSE_RELEASE: 'release',
            FUSE_INIT: 'init',
            FUSE_OPENDIR: 'opendir',
            FUSE_READDIR: 'readdir',
            FUSE_RELEASEDIR: 'releasedir',
           }

LEN, OPCODE, UNIQUE, NODEID, UID, GID, PID = range(7)


def mount_fuse(mount_point):
    rfd, sfd = socketpair(AF_UNIX, SOCK_STREAM)
    newenv = os.environ.copy()

    if not os.fork():
        os.environ['_FUSE_COMMFD'] = str(sfd)
        for i in xrange(3, 1024):
            if i != sfd:
                try:
                    os.close(i)
                except OSError:
                    pass
                os.execl('/usr/bin/fusermount', 'fusermount', mount_point)
    else:
        #s = socket.fromfd(rfd, AF_UNIX, SOCK_STREAM)
        message, flags, ancillary = recvmsg(rfd)
        level, type, fd = ancillary[0]
        return unpack('=i', fd)[0]

        #print fd
        #while 1:
        #    data = os.read(fd, 100)
        #    print repr(data)
        #    print len(data)
        #    print in_format.size
        #    pkg_len, opcode, unique, nodeid, uid, gid, pid =  in_format.unpack(data[:in_format.size])
        #    print pkg_len, opcode, unique, nodeid, uid, gid, pid
        #    print dispatch[opcode]
        #


class FUSEStream(iostream.IOStream):
    pass


class FUSEConnectionWrapper(object):
    def __init__(self, fd):
        self.fd = fd

    def setblocking(self, state):
        print self.fd
        s = socket.fromfd(self.fd, AF_UNIX, SOCK_STREAM)
        s.setblocking(state)

    def fileno(self):
        return self.fd

    def recv(self, chunk_size):
        print 'read fuse', chunk_size
        try:
            data = os.read(self.fd, chunk_size)
        except OSError:
            print 'nothing to read'
            raise socket.error(errno.EWOULDBLOCK)
        print len(data), repr(data)
        print
        return data

    def send(self, data):
        print 'write', repr(data)
        return os.write(self.fd, data)

    def close(self):
        print 'close fuse connection'


class FUSEConnection(object):
    def __init__(self, stream):
        self.stream = stream
        self.got_init = False
        self.read()
        #self.stream.set_close_callback(self.on_close)

    def read(self):
        self.stream.read_bytes(in_format.size, self.receive_pkg)

    def receive_pkg(self, data):
        data = in_format.unpack(data)
        method = getattr(self, 'handle_%s' % (dispatch.get(data[OPCODE], 'default'),), self.handle_default)
        method = partial(method, data)
        print 'fuse: incoming packet', dispatch.get(data[OPCODE], 'default'), data
        bytes_left = data[LEN] - in_format.size
        if bytes_left:
            self.stream.read_bytes(data[LEN] - in_format.size, method)
        else:
            method('')

    def handle_init(self, decode, data):
        self.got_init = True
        self.send_reply(0, decode[UNIQUE], pack('=II', FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION))
        major, minor, readahead, flags = unpack('=IIII', data[:16])
        print 'init', major, minor, readahead
        #assert major == FUSE_KERNEL_VERSION
        self.read()

    def handle_lookup(self, decode, data):
        # NULL terminator (why the fuck does FUSE decide to pass this?)
        name = data.rstrip('\x00')
        arg_out = ''
        res = -errno.ENOENT
        print name
        path = self.fs.get_path(decode[NODEID], name)
        if path is not None:
            res = -errno.ENOSYS
            if hasattr(self, 'getattr'):
                res, arg_out, nodeid = self.fs.lookup_path(decode[NODEID], decode[UNIQUE], name, path)
        res2 = self.send_reply(res, decode[UNIQUE], arg_out)
        if res == 0 and res2 == -errno.ENOENT:
            self.fs.forget_node(nodeid, decode[UNIQUE])

    def handle_forget(self, decode, arg):
        version, = unpack('=Q', arg)
        self.fs.forget_node(decode[NODEID], version)

    def handle_getattr(self, decode, _):
        res = -errno.ENOENT
        path = self.fs.get_path(decode[NODEID])
        arg_out = ''
        if path is not None:
            res = -errno.ENOSYS
            if hasattr(self, 'getattr'):
                res, stat = self.getattr(path)
        if not res:
            stat = filesys.copy_and_fill_stat(stat)
            # TODO: don't do this if flag FUSE_USE_INO is set
            stat['st_ino'] = decode[NODEID]
            arg_out = pack('=QII', filesys.ATTR_REVALIDATE_TIME, 0, 0) + filesys.pack_stat(stat)
        self.send_reply(res, decode[UNIQUE], arg_out)

    def handle_open(self, decode, arg):
        # XXX: guh how do I abstract this to filesys if it calls send_reply in the middle
        flags, = unpack('=I', arg)
        res = -errno.ENOENT
        path = self.fs.get_path(decode[NODEID])
        if path is not None:
            res = -errno.ENOSYS
            if hasattr(self, 'open'):
                res, handle = self.open(path, flags)
        if not res:
            res2 = self.send_reply(res, decode[UNIQUE], pack('=QI', handle, 0))
            if res2 == -errno.ENOENT:
                if hasattr(self, 'release'):
                    self.release(path, handle, flags)
            else:
                self.fs.id_table[decode[NODEID]].open_count += 1
        else:
            self.send_reply(res, decode[UNIQUE])

    def handle_read(self, decode, arg):
        res, arg_out = self.fs.read(decode[NODEID], *unpack('=QQI', arg))
        self.send_reply(res, decode[UNIQUE], arg_out)

    def handle_release(self, decode, arg):
        self.fs.release(decode[NODEID], *unpack('=QI', arg))
        self.send_reply(0, decode[UNIQUE])

    def handle_opendir(self, decode, _):
        handle = self.fs.opendir()
        self.send_reply(0, decode[UNIQUE], pack('=qI', handle, 0))

    def handle_readdir(self, decode, arg):
        res, arg_out = self.fs.readdir(decode[NODEID], *unpack('=qQI', arg))
        self.send_reply(res, decode[UNIQUE], arg_out)

    def handle_releasedir(self, decode, arg):
        self.fs.releasedir(*unpack('=qI', arg))
        self.send_reply(0, decode[UNIQUE])

    def handle_default(self, decode, _):
        self.send_reply(-errno.ENOSYS, decode[UNIQUE])

    def send_reply(self, error, unique, arg = ''):
        log.debug('fuse: outgoing u:%i e:%i arg:%s', unique , error, repr(arg))
        return self.stream.write(out_format.pack(out_format.size+len(arg), error, unique) + arg)


def main():
    fd = mount_fuse(sys.argv[1])
    #callback = partial(connection_ready, sock, worker)
    #stream = FUSEStream(connection, io_loop=io_loop)
    #FUSEStream
    #io_loop.add_handler(sock.fileno(), callback, io_loop.READ)
    if 0:
        print 'read'
        print repr(os.read(fd, 100))
        os.write(fd, '\x18\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00')
        #os.fsync(fd)
        print repr(os.read(fd, 100))
        return
    # pkg_len, opcode, unique, nodeid, uid, gid, pid =  in_format.unpack(data[:in_format.size])

    con = FUSEConnectionWrapper(fd)
    stream = FUSEStream(con)
    FUSEConnection(stream)
    print ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
print 'good bye'
#FuseDevice(sys.argv[1])