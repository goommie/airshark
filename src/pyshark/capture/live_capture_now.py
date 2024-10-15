# From https://github.com/KimiNewt/pyshark/issues/296

from pyshark.capture.live_capture import LiveCapture

import asyncio

class LiveCaptureNow(LiveCapture):
    """
    Live capture on a network interface using only tshark, not dumpcap.
    
    So as to avoid the (long) delays while the dumpcap input buffer fills when 
    listening for small infrequent packets on a quiet network.
    """ 

    # Just default to LiveCapture.__init__

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """

        # Use super(LiveCapture ...) NOT super(LiveCaptureNow ...), because that would use dumpcap,
        # which is what I am trying to avoid!
        params = super(LiveCapture, self).get_parameters(packet_count=packet_count)

        # Don't report packet counts, use pcap format
        params += ["-q", "-P"]
        if self.bpf_filter:
            params += ['-f', self.bpf_filter]
        if self.monitor_mode:
            params += ['-I']
        for interface in self.interfaces:
            params += ['-i', interface]
        # Send view of decoded output to STDOUT even if -w option is capturing raw pcap output as well
        params += ['-V']
        return params

    async def _get_tshark_process(self, packet_count=None, stdin=None):
        tshark = await super(LiveCapture, self)._get_tshark_process(packet_count=packet_count, stdin=stdin)
        return tshark