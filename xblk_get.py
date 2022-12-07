#!/usr/bin/python3
# jds: 5th December 2022
# Extracts XBLK NCO data from a wireshark export:
# File->Export packet dissections->as plain text->(Packet bytes only selected)

import argparse
import os
import re
import sys


def read_nco(xblk, index):
    return ((xblk[index]     <<  0) |
            (xblk[index + 1] <<  8) |
            (xblk[index + 2] << 16) |
            (xblk[index + 3] << 24))
    

# definition from DGP01144
# |X       |B       |L       |K       |       # XBLK header
# |seq LSB |seq MSB |len LSB |len MSB |   0-3 # Seqeunce number and Length
# |# of Blk|Blk Type|spare   |spare   |   4-7 # number of blocks, type, spare
# |chan 0  |ctl(0)  |level L |level M |  8-11 # Chan, 0, Level (two bytes)
# |cd NCO 1|cd NCO 2|cd NCO 3|cd NCO 4| 12-15 # 4 bytes of Code NCO
# |cr NCO 1|cr NCO 2|cr NCO 3|cr NCO 4| 16-19 # 4 bytes of Carrier NCO
# |chan 1  |ctl(0)  |level L |level M |  8 + channel * 4
# |cd NCO 1|cd NCO 2|cd NCO 3|cd NCO 4| 12 + channel * 4
# |cr NCO 1|cr NCO 2|cr NCO 3|cr NCO 4| 16 + channel * 4
# |chan 2  |ctl(0)  |level L |level M |
# |cd NCO 1|cd NCO 2|cd NCO 3|cd NCO 4|
# |cr NCO 1|cr NCO 2|cr NCO 3|cr NCO 4|
# |chan 3  |ctl(0)  |level L |level M |
# |cd NCO 1|cd NCO 2|cd NCO 3|cd NCO 4|
# |cr NCO 1|cr NCO 2|cr NCO 3|cr NCO 4|
#
def grab_nco(xblk, sir_ms):
    output_line = ""
    # print(f'In grab_nco, using sequence increment of {sir_ms} ')

    # unfold the message into CSV
    sequence_number = (xblk[1] << 8) | xblk[0]
    output_line += (f'{sequence_number}, ')
    output_line += (f'0x{sequence_number:04x}, ')
    output_line += (f'{sequence_number * int(sir_ms) / 1e3}, ')

    level_line = ""

    channel_count = xblk[4]
    xblk_type = xblk[5]
    # output_line += f'{xblk_type}, '

    carrier_line = ""
    carrier_nco_list = []
    code_line = ""
    code_nco_list = []

    if (0 == xblk_type):
        # print(f'channel_count {channel_count}')
        for channel in range(channel_count):
            # level
            level = xblk[11] << 8 | xblk[10]
            level_line += f'{level}, '
            # if 2000 != level:
                # print( "level not 2000" );

            # carrier NCO
            index = 12 + (4 * channel)
            carrier_nco = read_nco(xblk, index)
            carrier_nco_list.append(carrier_nco)
            carrier_line += f'{carrier_nco}, '

            # code NCO
            index = 16 + (4 * channel)
            code_nco = read_nco(xblk, index)
            code_nco_list.append(code_nco)
            code_line += f'{code_nco}, '

        # output_line += f'{carrier_line}{code_line}{level_line}'
        output_line += f'{carrier_line}{code_line}'

        output_line += f'{carrier_nco_list[0] - carrier_nco_list[3]}, '
        output_line += f'{carrier_nco_list[1] - carrier_nco_list[4]}, '
        output_line += f'{carrier_nco_list[2] - carrier_nco_list[5]}, '
        output_line += f'{carrier_nco_list[6] - carrier_nco_list[7]}, '

        output_line += f'{code_nco_list[0] - code_nco_list[3]}, '
        output_line += f'{code_nco_list[1] - code_nco_list[4]}, '
        output_line += f'{code_nco_list[2] - code_nco_list[5]}, '
        output_line += f'{code_nco_list[6] - code_nco_list[7]}, '
    elif (3 == xblk_type):
        # fader_line = f'XBLK type 3 (chan_count {channel_count}), '
        fader_line = f'(chan_count {channel_count}), '
        for channel in range(channel_count):
            fader_line += f'chan {xblk[8 + channel * 2]} '
            data = xblk[9 + channel * 2]
            scale = (data & 0xc) >> 6
            if ( 0 == scale ):
                offset_range = data & 0x1f 
                offset_range *= 0.01
                offset_sign_bit = data & 0x20
                offset = offset_range
                if ( offset_sign_bit ):
                    offset *= -1
                # fader_line += f'data {data}: scale {scale:02b} offset {offset}m, '
                fader_line += f'offset {offset}m, '
            else:
                offset = data &0x3f
                fader_line += f'data {data}: scale {scale:02b} offset {offset}(raw), '


            
        output_line += fader_line
    else:
        output_line += f'unsupported XBLK type {xblk_type}'


    # print(output_line)
    return output_line


input_filename = "test_input_03.txt"

parser = argparse.ArgumentParser(
    description="Parse a TCP dump file for XBLK contents")
parser.add_argument(
    "filename", help="The input file, exported from Wireshark as "
    "File->Export packet dissections->as plain text->(Packet bytes only "
    "selected")
parser.add_argument(
    "SIR", help="The SIR in miliseconds")
args = parser.parse_args()

if args.filename:
    input_filename = args.filename
    print(f"Input file selected: {input_filename}")
else:
    print(f"Using default input file {input_filename}")

sir_ms = args.SIR

xblk_message = []
nco_data = []
xblk_found = False

print("sequence number, sequence number, XBLK type, "
      "chan 1, chan 2, chan 3, chan 4, chan 5, chan 6, chan 7, chan 8, "
      "chan 1, chan 2, chan 3, chan 4, chan 5, chan 6, chan 7, chan 8, "
      # "level 1, level 2, level 3, level 4, level 5, level 6, level 7, level 8, "
      "chan 1 - chan 4, chan 2 - chan 5, chan 3 - chan 6, chan 7 - chan 8, ")

with open(input_filename) as infile:
    line_number = 0

    for input_line in infile:
        line_number += 1
        line = re.sub(os.sep, "", input_line)
        if len(line) < 2:
            # print('end of record')

            if (xblk_found):
                # print(f'xblk_message is {xblk_message}')

                # work out what the nco number is
                nco_data_string = grab_nco(xblk_message, sir_ms)
                nco_data.append(nco_data_string)
                print(nco_data_string)

                xblk_message = []
                xblk_found = False
            else:
                # probably nav data
                if navd_found:
                    navd_found = False
                    print(f'input line {line_number} not parsed, NAVD')
                else:
                    print(f'input line {line_number} not parsed, unknown')
            continue

        # print(f'line {line_number} is {line}')
        if not xblk_found and re.search("XBLK", line):
            xblk_found = True
            # skip this line and go on to the next
            continue

        if not xblk_found and re.search("NAVD", line):
            navd_found = True
            continue

        if xblk_found:
            # start parsing the data
            (address, data, *rest) = re.split("  ", line)
            # print(f'data is {data}')

            data_bytes_ascii = re.split(" ", data)
            for byte in data_bytes_ascii:
                xblk_message.append(int(byte, 16))
        else:
            # ignore the other lines
            pass

# print(f'nco_data is {nco_data}')


# while( $line = <>)
# {
#     chomp( $line );
#     next unless $line =~ /XBLK\$/;
#     my ( $dummy1, $data, @rest ) = split(/  /, $line);
#     my @line_bytes = split(/ /, $data);
#
#     for @line_bytes
#
# }
#
