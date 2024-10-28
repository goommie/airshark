import pathlib
import time

from pyshark.capture.file_capture import FileCapture


class FileCaptureNow(FileCapture):
    """A class representing a capture read from a file, simulating live capture by preserving packet timings."""

    def __init__(self, input_file=None, keep_packets=True, display_filter=None, only_summaries=False,
                 decryption_key=None, encryption_type="wpa-pwk", decode_as=None,
                 disable_protocol=None, tshark_path=None, override_prefs=None,
                 use_json=False, use_ek=False,
                 output_file=None, include_raw=False, eventloop=None, custom_parameters=None,
                 debug=False):
        super(FileCaptureNow, self).__init__(
            input_file=input_file,
            keep_packets=keep_packets,
            display_filter=display_filter,
            only_summaries=only_summaries,
            decryption_key=decryption_key,
            encryption_type=encryption_type,
            decode_as=decode_as,
            disable_protocol=disable_protocol,
            tshark_path=tshark_path,
            override_prefs=override_prefs,
            use_json=use_json,
            use_ek=use_ek,
            output_file=output_file,
            include_raw=include_raw,
            eventloop=eventloop,
            custom_parameters=custom_parameters,
            debug=debug
        )

        # Initialize variables for timing
        self._capture_start_time = None

        # Wrap the original packet generator to introduce delays
        self._original_packet_generator = self._packet_generator
        self._packet_generator = self._packet_generator_with_delay(self._original_packet_generator)

    def _packet_generator_with_delay(self, original_generator):
        """A generator that yields packets with delays to simulate live capture."""
        for packet in original_generator:
            # Get the time since the first packet (in seconds)
            packet_time_relative = float(packet.frame_info.time_relative)

            if self._capture_start_time is None:
                # First packet initialization
                self._capture_start_time = time.perf_counter()
                time_diff = 0
            else:
                # Calculate elapsed real time since processing started
                real_time_since_start = time.perf_counter() - self._capture_start_time
                # Calculate time to sleep to align with the original capture timing
                time_diff = packet_time_relative - real_time_since_start

            # Optional: Debugging output to trace computation values
            # print(f"Packet {packet.number}: packet_time_relative={packet_time_relative}, "
            #       f"real_time_since_start={real_time_since_start}, time_diff={time_diff}")

            if time_diff > 0:
                time.sleep(time_diff)

            yield packet

    def __repr__(self):
        if self.keep_packets:
            return f"<{self.__class__.__name__} {self.input_filepath.as_posix()}>"
        else:
            return f"<{self.__class__.__name__} {self.input_filepath.as_posix()} ({len(self._packets)} packets)>"
