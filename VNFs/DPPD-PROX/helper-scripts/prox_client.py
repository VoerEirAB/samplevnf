################################################################################
# Copyright (c) 2019-present VoerEir AB - All Rights Reserved                  #
# Unauthorized copying of this file, via any medium is strictly prohibited     #
# Proprietary and confidential                                                 #
# Written By: Dheeraj Dang <dang@voereir.com>, December 2019                   #
################################################################################
import argparse
import datetime
import json
import socket
import sys
import time
from datetime import timezone


# ***** PROX Utility Class to talk with PROX process on local machine ******* #


class ProxUtility(object):
    """ Class that talks with PROX process, execute commands """

    ALLOWED_OPERATIONS = [
        'start', 'stop', 'tot_stats', 'reset_stats', 'quit',
        'lat_stats', 'lat_all_stats', 'lat_tot_stats', 'dp_core_stats']
    DEFAULT_PORT = 8474

    def __init__(self, sock):
        self._sock = sock
        self._received = b''

    def __del__(self):
        if self._sock:
            self._sock.close()
            self._sock = None

    def _send(self, cmd_string):
        """ Send command to the PROX """
        self._sock.sendall(cmd_string.encode() + b'\n')

    def _recv(self):
        """ Receive response from PROX instance. """
        pos = self._received.find(b'\n')
        while pos == -1:
            self._received += self._sock.recv(256)
            pos = self._received.find(b'\n')
        response = self._received[:pos]
        self._received = self._received[pos + 1:]
        return response

    def _recv_multiline(self):
        """ Receive multiline response from PROX instance (for histogram data). """
        try:
            full_response = b''
            
            # Set a short timeout for multiline responses
            original_timeout = self._sock.gettimeout()
            self._sock.settimeout(2.0)  # 2 second timeout for histogram data
            
            try:
                while True:
                    try:
                        chunk = self._sock.recv(4096)
                        if not chunk:
                            # Empty chunk means no more data or connection closed
                            break
                        full_response += chunk
                    except socket.timeout:
                        # Timeout means no more data is coming
                        break
            finally:
                # Restore original timeout
                if original_timeout is not None:
                    self._sock.settimeout(original_timeout)
                else:
                    self._sock.settimeout(None)
            
            # Parse the response
            if full_response:
                response_lines = full_response.decode('utf-8', errors='ignore').strip().split('\n')
                # Filter out empty lines
                response_lines = [line.strip() for line in response_lines if line.strip()]
                return response_lines
            
            return []
        except Exception as e:
            raise RuntimeError(f'PROX failed to read multi-line response: {e}')

    def _parse_histogram_response(self, response_lines, bucket_prefix="Bucket"):
        """
        Parse histogram response lines from PROX latency commands.
        
        This method processes multiline responses from PROX 'lat all stats' and 'lat tot stats'
        commands, extracting bucket histogram data and configuration information.
        
        :param response_lines: List of response lines received from PROX socket
        :param bucket_prefix: Bucket identifier prefix - "Bucket" for lat_all_stats, 
                             "Total Bucket" for lat_tot_stats
        :return: tuple of (histogram_data, bucket_info) where:
                 - histogram_data: dict mapping bucket names to packet counts
                 - bucket_info: dict with bucket_size and frequency_hz metadata
        """
        histogram_data = {}
        bucket_info = {
            'bucket_size': None,
            'frequency_hz': None
        }

        for line in response_lines:
            # Parse bucket size and frequency info
            if 'Bucket size is' in line and 'freq is' in line:
                try:
                    parts = line.split(',')
                    for part in parts:
                        part = part.strip()
                        if part.startswith('Bucket size is'):
                            bucket_size_str = part.replace('Bucket size is', '').strip()
                            bucket_info['bucket_size'] = int(bucket_size_str)
                        elif part.startswith('freq is'):
                            freq_str = part.replace('freq is', '').strip()
                            bucket_info['frequency_hz'] = int(freq_str)
                except (ValueError, IndexError):
                    continue

            # Parse bucket data with flexible prefix
            elif line.startswith(f'{bucket_prefix} [') and ']:' in line:
                try:
                    bucket_part, count_part = line.split(']: ', 1)
                    bucket_num = bucket_part.split('[')[1]  # Extract X from "Bucket [X" or "Total Bucket [X"
                    count = int(count_part)
                    histogram_data[f'{bucket_prefix} [{bucket_num}]'] = count
                except (ValueError, IndexError):
                    continue

        return histogram_data, bucket_info

    def _get_latency_histogram_stats(self, command, bucket_prefix, **kwargs):
        """
        Common implementation for collecting latency histogram statistics from PROX.
        
        This method handles the complete workflow of sending histogram commands to PROX,
        receiving multiline responses, parsing bucket data, and formatting results.
        Used by both lat_all_stats() and lat_tot_stats() methods.
        
        :param command: PROX socket command string ('lat all stats' or 'lat tot stats')
        :param bucket_prefix: Bucket line prefix for parsing ('Bucket' or 'Total Bucket')
        :param kwargs: Command parameters containing:
                      - iterations: Number of histogram collections to perform
                      - core: CPU core ID for latency measurement
                      - task: Task ID on the specified core
                      - sleep: Sleep duration between iterations in seconds
        :return: JSON string containing histogram data for all iterations with metadata
        """
        iterations = kwargs['iterations']
        core = kwargs['core']
        task = kwargs['task']
        sleep_in_seconds = kwargs['sleep']
        data_dict = {}
        
        for iteration_string in map(str, range(1, iterations + 1)):
            time.sleep(sleep_in_seconds)
            self._send('{} {} {}'.format(command, core, task))
            
            dt = datetime.datetime.now(timezone.utc)
            utc_time = dt.replace(tzinfo=timezone.utc)
            utc_timestamp = utc_time.timestamp()
            
            # Read the multiline response
            response_lines = self._recv_multiline()
            
            # Parse histogram data using common method
            histogram_data, bucket_info = self._parse_histogram_response(response_lines, bucket_prefix)

            iter_data = {
                'Iteration': iteration_string,
                'Timestamp': utc_timestamp,
                'Core': core,
                'Task': task,
                'Bucket_Info': bucket_info,
                'Histogram': histogram_data,
                'Bucket_Count': len(histogram_data)
            }
            data_dict.update({iteration_string: iter_data})
        
        return json.dumps(data_dict)

    def start(self, **kwargs):
        """ Method that starts all tasks """
        if kwargs.get('core') and kwargs.get('task'):
            self._send('start {} {}'.format(kwargs['core'], kwargs['task']))
        else:
            self._send('start all')

    def stop(self, **kwargs):
        """ Method that stops the running tasks."""
        core = kwargs['core']
        task = kwargs['task']
        self._send('stop {} {}'.format(core, task))
        output = self._recv().decode()
        if output == 'Failure':
            if core == 'all' and task == 'all':
                error_msg = 'PROX failed to stop core(s).'
            else:
                error_msg = ('PROX failed to stop '
                             'task {} on core {}.'.format(task, core))
            raise RuntimeError(error_msg)
        return output

    def quit(self, **kwargs):
        """ Method to be used for quiting PROX connection """
        if self._sock is not None:
            self._send('quit')

    def reset_stats(self, **kwargs):
        """ Method to reset stats """
        self._send('reset stats')
        return self.total_stats()

    def total_stats(self, **kwargs):
        """ Method that will return total TX and RX packets of DUT """
        self._send('tot stats')
        tx_packets, rx_packets = 0, 0
        tx_rx_stats = self._recv().split(b',')
        if len(tx_rx_stats[:-2]):
            rx_packets = int(tx_rx_stats[0])
            tx_packets = int(tx_rx_stats[1])
        return json.dumps({'tx_packets': tx_packets,
                           'rx_packets': rx_packets})

    def dp_core_stats(self, **kwargs):
        """
        Get rx/tx/non_dp_rx/non_dp_tx/drop
        for the specified task running on specified core.
        rx -> no. of packets received
        tx -> no. of packets sent
        non_dp_rx -> no. of packets received having bad signature/length
        non_dp_tx -> no. of packets sent having bad signature/length
        drop -> no. of packets dropped
        :keyword core_id: Core ID of the desired core
        :keyword task_id: Task ID of the desired task
        :return rx_packets, tx_packets, rx_non_dp, tx_non_dp, drop
        """
        core = kwargs['core']
        task = kwargs['task']
        self._send('dp core stats {} {}'.format(core, task))
        rx, tx, rx_non_dp, tx_non_dp, drop = list(
            map(int, self._recv().split(b',')[:5]))
        stdout = json.dumps({
            'rx_packets': rx,
            'tx_packets': tx,
            'rx_non_dp': rx_non_dp,
            'tx_non_dp': tx_non_dp,
            'drop': drop
        })
        return stdout

    def lat_stats(self, **kwargs):
        """
        Print min,max,avg latency for specified iterations.
        :keyword core_id: Core ID of the desired core
        :keyword task_id: Task ID of the desired task
        :keyword iterations: Number of times latency will be calculated.
        :keyword sleep: Amount of time process sleeps.
        :return: min,max,avg latency values for all the iterations.
        """
        iterations = kwargs['iterations']
        core = kwargs['core']
        task = kwargs['task']
        sleep_in_seconds = kwargs['sleep']
        data_dict = {}
        for iteration_string in map(str, range(1, iterations + 1)):
            # Story: #182436676
            # sleep before fetching result to remove incorrect iteration result.
            time.sleep(sleep_in_seconds)
            self._send('lat stats {} {}'.format(core, task))

            stats = list(map(int, self._recv().split(b',')[:3]))
            min = max = avg = 0
            dt = datetime.datetime.now(timezone.utc)
            utc_time = dt.replace(tzinfo=timezone.utc)
            utc_timestamp = utc_time.timestamp()
            if len(stats):
                min, max, avg = stats
            iter_data = {
                'Iteration': iteration_string,
                'Minimum Latency': min,
                'Maximum Latency': max,
                'Average Latency': avg,
                'Timestamp': utc_timestamp
            }
            data_dict.update({iteration_string: iter_data})

        return data_dict

    def lat_all_stats(self, **kwargs):
        """
        Collect current latency histogram distribution from PROX showing packets per second.
        
        Executes the PROX 'lat all stats' command to get instantaneous latency 
        histogram data showing the distribution of packet latencies across buckets
        as packets per second rates. This provides a snapshot of current latency
        distribution rates at the time of measurement.
        
        :param kwargs: Parameters passed to _get_latency_histogram_stats():
                      - iterations: Number of histogram snapshots to collect
                      - core: Core ID of the latency measurement core  
                      - task: Task ID on the specified core (typically 0 for latency tasks)
                      - sleep: Sleep duration between iterations in seconds
        :return: JSON string containing histogram data with bucket distribution,
                 bucket configuration (size, frequency), and timestamps
        """
        return self._get_latency_histogram_stats('lat all stats', 'Bucket', **kwargs)


    def lat_tot_stats(self, **kwargs):
        """
        Collect accumulated latency histogram data from PROX showing total packet counts.
        
        Executes the PROX 'lat tot stats' command to get cumulative latency 
        histogram data that has been accumulated since the last statistics reset.
        This provides the total count of packets in each latency bucket measured
        during the entire test period, useful for comprehensive latency analysis.
        
        :param kwargs: Parameters passed to _get_latency_histogram_stats():
                      - iterations: Number of total histogram snapshots to collect
                      - core: Core ID of the latency measurement core
                      - task: Task ID on the specified core (typically 0 for latency tasks)  
                      - sleep: Sleep duration between iterations in seconds
        :return: JSON string containing accumulated histogram data with total bucket
                 packet counts, bucket configuration (size, frequency), and timestamps
        """
        return self._get_latency_histogram_stats('lat tot stats', 'Total Bucket', **kwargs)

# **************** Command Parser and main method *************************** #

class ValidateOperation(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        argparse.Action.__init__(self, option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        valid_operations = ProxUtility.ALLOWED_OPERATIONS
        if values not in valid_operations:
            raise ValueError('%s is not a valid operation, allowed operations '
                             'are %s' % (values, '/'.join(valid_operations)))
        else:
            setattr(namespace, self.dest, values)


def get_parser():
    parser = argparse.ArgumentParser(add_help=True)

    parser.add_argument(
        '-m', '--command', type=str, required=True,
        action=ValidateOperation,
        help='PROX operation to be performed ('
             'start/stop/tot_stats/reset_stats/lat_stats/lat_all_stats/lat_tot_stats)'
    )
    parser.add_argument(
        '-c', '--core-id', type=str, required=False, default='all',
        help='CPU Core Id'
    )
    parser.add_argument(
        '-t', '--task-id', type=str, required=False, default='all',
        help='Task Id'
    )
    parser.add_argument(
        '-i', '--iterations', type=int, required=False, default=1,
        help='Total number of iterations'
    )
    parser.add_argument(
        '-s', '--sleep', type=int, required=False, default=1,
        help='Sleep Duration (in seconds)'
    )
    parser.add_argument(
        '-ts', '--timestamp', action='store_true',
        help='Include epoch time (in ns) of the command when it is executed'
    )
    parser.set_defaults(timestamp=False)
    return parser


def execute_prox_command(args):
    # create PROX socket connnection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('localhost', int(ProxUtility.DEFAULT_PORT)))
    except socket.error as e:
        return 1, None, str(e)

    prox_wrapper = ProxUtility(sock=sock)
    params = get_command_parameters(args)
    command = str(args.command)
    if command == 'start':
        method_cb = prox_wrapper.start
    elif command == 'stop':
        method_cb = prox_wrapper.stop
    elif command == 'reset_stats':
        method_cb = prox_wrapper.reset_stats
    elif command == 'tot_stats':
        method_cb = prox_wrapper.total_stats
    elif command == 'quit':
        method_cb = prox_wrapper.quit
    elif command == 'lat_stats':
        method_cb = prox_wrapper.lat_stats
    elif command == 'lat_all_stats':
        method_cb = prox_wrapper.lat_all_stats
    elif command == 'lat_tot_stats':
        method_cb = prox_wrapper.lat_tot_stats
    elif command == 'dp_core_stats':
        method_cb = prox_wrapper.dp_core_stats
    else:
        raise Exception('Invalid operation provided {}, '
                        'it should never happen.'.format(command))

    try:
        output = method_cb(**params)
        return 0, output, None
    except RuntimeError as e:
        err_msg = 'Error: %s' % str(e)

        sock.close()  # close connection in case of error
        return 1, None, err_msg


def get_command_parameters(args):
    params = {
        'core': args.core_id,
        'task': args.task_id,
        'iterations': args.iterations,
        'sleep': args.sleep,
    }
    return params


def main():
    parser = get_parser()
    args = parser.parse_args()
    pre_timestamp = time.time_ns()
    rc, output, error = execute_prox_command(args)
    post_timestamp = time.time_ns()
    if args.timestamp:
        print(pre_timestamp, file=sys.stdout)
        print(post_timestamp, file=sys.stdout)

    if output:
        print(output, file=sys.stdout)
    if error:
        print(error, file=sys.stderr)
    return rc


if __name__ == '__main__':
    sys.exit(main())
