from pyshark.capture.capture import Capture
from datetime import datetime
import time

class FileCaptureNow(Capture):
    """
    A capture object that reads from a pcap/pcapng file but yields packets in real-time,
    simulating a live capture based on the original packet timestamps.
    """
    
    def __init__(self, input_file, display_filter=None, only_summaries=False,
                 decryption_key=None, encryption_type='wpa-pwk', **kwargs):
        """
        Creates a new packet capture from a file, yielding packets with original timing.
        
        Args:
            input_file: Path to the pcap/pcapng file to read from
            display_filter: Wireshark display filter to use
            only_summaries: Only produce packet summaries (default: False)
            decryption_key: Optional key to decrypt encrypted packets
            encryption_type: Type of encryption key (default: wpa-pwk)
            **kwargs: Additional arguments to pass to tshark
        """
        super(FileCaptureNow, self).__init__(display_filter=display_filter, only_summaries=only_summaries,
                                            decryption_key=decryption_key, encryption_type=encryption_type, **kwargs)
        self.input_file = input_file
        self._current_batch = []
        self._batch_start_time = None
        self._first_packet_time = None

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = super(FileCaptureNow, self).get_parameters(packet_count=packet_count)
        params.extend(['-r', self.input_file])
        return params

    def _get_packet_timestamp(self, packet):
        """
        Extract the timestamp from a packet.
        
        Args:
            packet: Packet object from pyshark
            
        Returns:
            float: Unix timestamp of the packet
        """
        try:
            return float(packet.frame_info.time_epoch)
        except AttributeError:
            # If time_epoch is not available, try to parse the time field
            time_str = packet.frame_info.time
            dt = datetime.strptime(time_str, '%b %d, %Y %H:%M:%S.%f %Z')
            return dt.timestamp()

    def _calculate_sleep_time(self, packet):
        """
        Calculate how long to sleep before yielding this packet.
        
        Args:
            packet: Packet object from pyshark
            
        Returns:
            float: Time to sleep in seconds (can be negative if we're behind schedule)
        """
        packet_time = self._get_packet_timestamp(packet)
        
        if self._first_packet_time is None:
            self._first_packet_time = packet_time
            self._batch_start_time = time.time()
            return 0
        
        relative_packet_time = packet_time - self._first_packet_time
        relative_real_time = time.time() - self._batch_start_time
        
        return relative_packet_time - relative_real_time

    def sniff_continuously(self, packet_count=None):
        """
        Captures from the file and yields packets based on their original timing.
        
        Args:
            packet_count: Number of packets to capture (default: None, meaning all packets)
            
        Yields:
            Packet objects in real-time according to their original capture timestamps
        """
        # Reset timing variables
        self._first_packet_time = None
        self._batch_start_time = None
        
        try:
            for packet in self._packets_from_tshark_sync(packet_count=packet_count):
                sleep_time = self._calculate_sleep_time(packet)
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
                yield packet
                
        except StopIteration:
            pass
        finally:
            self.close()

    def load_packets(self, packet_count=None):
        """
        Loads all packets without real-time delays. Overrides parent method.
        
        Args:
            packet_count: Number of packets to read (default: None, meaning all packets)
            
        Returns:
            List of packets
        """
        return list(self._packets_from_tshark_sync(packet_count=packet_count))

    __iter__ = sniff_continuously