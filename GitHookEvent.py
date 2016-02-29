#!/usr/bin/env python

from BaseHTTPServer import BaseHTTPRequestHandler

class WebhookRequestHandler(BaseHTTPRequestHandler):
    """Extends the BaseHTTPRequestHandler class and handles the incoming HTTP requests."""

    def do_POST(self):
        # Extract repository URL(s) from incoming request body
        git_commit = self.parse_gitlab_request()

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        import pprint
        print "git_comit: "
        pprint.pprint(git_commit)

        GitHookEvent.process_request(git_commit)

    def do_GET(self):
        import pprint
        pprint.pprint(self.path)

    def parse_gitlab_request(self):
        """Parses the incoming request and extracts all possible URLs to the repository in question. Since repos can
        have both ssh://, git:// and https:// URIs, and we don't know which of them is specified in the config, we need
        to collect and compare them all."""
        import json

        content_type = self.headers.getheader('content-type')
        length = int(self.headers.getheader('content-length'))
        body = self.rfile.read(length)

        data = json.loads(body)

        gitlab_event = self.headers.getheader('X-Gitlab-Event')

        # Assume GitLab if the X-Gitlab-Event HTTP header is set
        if gitlab_event:

            print "Received '%s' event from GitLab" % gitlab_event

            gitlab = {
                'path': self.path,
                'sha': data['checkout_sha'],
                'tag': data['ref'].split('/',3)[2],
            }

        else:
            print "ERROR - Unable to recognize request origin. Don't know how to handle the request."

        return gitlab

class GitHookEvent(object):
    config_path = None
    debug = True
    daemon = False

    _instance = None
    _server = None
    _config = None

    def __new__(cls, *args, **kwargs):
        """Overload constructor to enable Singleton access"""
        if not cls._instance:
            cls._instance = super(GitHookEvent, cls).__new__(
                cls, *args, **kwargs)
        return cls._instance

    @staticmethod
    def process_request(req):
        import urlparse

        gocd_profiles = GitHookEvent().get_config()[ 'gocd_profiles' ]

        url = urlparse.urlparse(req['path'])
        param = urlparse.parse_qs(url.query)

        if 'gocd_profile' in param.keys():
            if param['gocd_profile'] in gocd_profiles.keys():
                gocd = gocd_profiles[ param['gocd_profile'] ]
            else:
                print "Error: gocd profile "+param['gocd_profile']+" not found in list of profiles: "+', '.join(gocd_profiles.keys())
                return

        elif 'host' in param.keys() and 'port' in param.keys() and 'user' in param.keys() and 'pass' in param.keys():
            gocd = {
                'url': 'http://'+param['host']+':'+param['port'],
                'user': param['user'],
                'pass': param['pass']
            }

        else:
            print "Error: gocd profile not defined"
            return

        print "GO.CD API: curl -u '"+gocd['user']+":"+gocd['pass']+"' -X POST --data 'materials["+param['material']+"]="+req['sha']+"&variables[GIT_TAG]="+req['tag']+"' "+gocd['url']+"/go/api/pipelines/"+param['pipeline']+"/schedule"

    def get_default_config_path(selfs):
        return './githookevent.conf.json'

    def get_config(self):
        import json
        import sys
        import os
        import re

        if self._config:
            return self._config

        if not self.config_path:
            self.config_path = self.get_default_config_path()

        try:
            config_string = open(self.config_path).read()

        except Exception as e:
            print "Could not load %s file\n" % self.config_path
            raise e

        try:
            self._config = json.loads(config_string)

        except Exception as e:
            print "%s file is not valid JSON\n" % self.config_path
            raise e

        # Translate any ~ in the path into /home/<user>
        if 'pidfilepath' in self._config:
            self._config['pidfilepath'] = os.path.expanduser(self._config['pidfilepath'])

        return self._config

    @staticmethod
    def debug_diagnosis(port):
        if GitHookEvent.debug is False:
            return

        pid = GitHookEvent.get_pid_on_port(port)
        if pid is False:
            print 'I don\'t know the number of pid that is using my configured port'
            return

        print 'Process with pid number %s is using port %s' % (pid, port)
        with open("/proc/%s/cmdline" % pid) as f:
            cmdline = f.readlines()
            print 'cmdline ->', cmdline[0].replace('\x00', ' ')

    @staticmethod
    def get_pid_on_port(port):
        import os

        with open("/proc/net/tcp", 'r') as f:
            file_content = f.readlines()[1:]

        pids = [int(x) for x in os.listdir('/proc') if x.isdigit()]
        conf_port = str(port)
        mpid = False

        for line in file_content:
            if mpid is not False:
                break

            _, laddr, _, _, _, _, _, _, _, inode = line.split()[:10]
            decport = str(int(laddr.split(':')[1], 16))

            if decport != conf_port:
                continue

            for pid in pids:
                try:
                    path = "/proc/%s/fd" % pid
                    if os.access(path, os.R_OK) is False:
                        continue

                    for fd in os.listdir(path):
                        cinode = os.readlink("/proc/%s/fd/%s" % (pid, fd))
                        minode = cinode.split(":")

                        if len(minode) == 2 and minode[1][1:-1] == inode:
                            mpid = pid

                except Exception as e:
                    pass

        return mpid
        
    def kill_conflicting_processes(self):
        import os

        pid = GitHookEvent.get_pid_on_port(self.get_config()['port'])

        if pid is False:
            print '[KILLER MODE] I don\'t know the number of pid that is using my configured port\n ' \
                  '[KILLER MODE] Maybe no one? Please, use --force option carefully'
            return False

        os.kill(pid, signal.SIGKILL)
        return True

    def create_pid_file(self):
        import os

        with open(self.get_config()['pidfilepath'], 'w') as f:
            f.write(str(os.getpid()))

    def read_pid_file(self):
        with open(self.get_config()['pidfilepath'], 'r') as f:
            return f.readlines()

    def remove_pid_file(self):
        import os

        os.remove(self.get_config()['pidfilepath'])

    def exit(self):
        import sys

        print '\nGoodbye'
        self.remove_pid_file()
        sys.exit(0)

    @staticmethod
    def create_daemon():
        import os

        try:
            # Spawn first child
            pid = os.fork()
        except OSError, e:
            raise Exception("%s [%d]" % (e.strerror, e.errno))

        # First child
        if pid == 0:
            os.setsid()

            try:
                # Spawn second child
                pid = os.fork()
            except OSError, e:
                raise Exception, "%s [%d]" % (e.strerror, e.errno)

            if pid == 0:
                os.chdir('/')
                os.umask(0)
            else:
                # Kill first child
                os._exit(0)
        else:
            # Kill parent of first child
            os._exit(0)

        import resource

        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if maxfd == resource.RLIM_INFINITY:
            maxfd = 1024

        # Close all file descriptors
        for fd in range(0, maxfd):
            try:
                os.close(fd)
            except OSError:
                # Ignore errors if fd isn't opened
                pass

        # Redirect standard input, output and error to devnull since we won't have a terminal
        os.open(os.devnull, os.O_RDWR)
        os.dup2(0, 1)
        os.dup2(0, 2)

        return 0

    def run(self):
        from sys import argv
        import sys
        from BaseHTTPServer import HTTPServer
        import socket
        import os

        if '-d' in argv or '--daemon-mode' in argv:
            self.daemon = True

        if '--ssh-keygen' in argv:
            print 'Scanning repository hosts for ssh keys...'
            self.ssh_key_scan()

        if '--force' in argv:
            print 'Attempting to kill any other process currently occupying port %s' % self.get_config()['port']
            self.kill_conflicting_processes()

        if '--config' in argv:
            pos = argv.index('--config')
            if len(argv) > pos + 1:
                self.config_path = os.path.realpath(argv[argv.index('--config') + 1])
                print 'Using custom configuration file \'%s\'' % self.config_path

        # Initialize config
        self.get_config()

        if self.daemon:
            print 'Starting Git Auto Deploy in daemon mode'
            GitHookEvent.create_daemon()
        else:
            print 'Git Auto Deploy started'

        self.create_pid_file()

        # Suppress output
        if '-q' in argv or '--quiet' in argv:
            sys.stdout = open(os.devnull, 'w')

        try:
            self._server = HTTPServer((self.get_config()['host'], self.get_config()['port']), WebhookRequestHandler)
            sa = self._server.socket.getsockname()
            print "Listening on", sa[0], "port", sa[1]
            self._server.serve_forever()

        except socket.error, e:

            if not GitHookEvent.daemon:
                print "Error on socket: %s" % e
                GitHookEvent.debug_diagnosis(self.get_config()['port'])

            sys.exit(1)

    def stop(self):
        if self._server is not None:
            self._server.socket.close()

    def signal_handler(self, signum, frame):
        self.stop()

        if signum == 1:
            self.run()
            return

        elif signum == 2:
            print '\nRequested close by keyboard interrupt signal'

        elif signum == 6:
            print 'Requested close by SIGABRT (process abort signal). Code 6.'

        self.exit()


if __name__ == '__main__':
     import signal

     app = GitHookEvent()

     signal.signal(signal.SIGHUP, app.signal_handler)
     signal.signal(signal.SIGINT, app.signal_handler)
     signal.signal(signal.SIGABRT, app.signal_handler)
     signal.signal(signal.SIGPIPE, signal.SIG_IGN)

     app.run()
     