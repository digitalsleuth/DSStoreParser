#!/usr/bin/python3
# -*- coding: utf-8 -*-
# DSStoreParser
# ------------------------------------------------------
# Copyright 2019 G-C Partners, LLC
# Nicole Ibrahim
#
# G-C Partners licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

# Modified by: Nicole Ibrahim
# Update for Python 3 by: Corey Forman


import fnmatch
import sys
import os
import argparse
import datetime
from time import strftime
import unicodecsv as csv
from ds_store_parser.ds_store import ds_store_handler
from ds_store_parser.ds_store.store import codes as type_codes


'''
try:
    from dfvfs.analyzer import analyzer
    from dfvfs.lib import definitions
    from dfvfs.path import factory as path_spec_factory
    from dfvfs.volume import tsk_volume_system
    from dfvfs.resolver import resolver
    from dfvfs.lib import raw
    from dfvfs.helpers import source_scanner
    DFVFS_IMPORT = True
    IMPORT_ERROR = None

except ImportError as exp:
    DFVFS_IMPORT = False
    IMPORT_ERROR =("\n%s\n\
        You have specified the source type as image but DFVFS \n\
        is not installed and is required for image support. \n\
        To install DFVFS please refer to \n\
        http://www.hecfblog.com/2015/12/how-to-install-dfvfs-on-windows-without.html" % (exp))
'''
__VERSION__ = "1.0.0"
folder_access_report = None
other_info_report = None
all_records_ds_store_report = None
records_parsed = 0


class RecordHandler(object):
    def __init__(self, opts_check):
        global folder_access_report, other_info_report, all_records_ds_store_report
        if opts_check:
            fields = [
                "generated_path",
                "record_filename",  # filename
                "record_type",      # code
                "record_format",    # type
                "record_data",      # value
                "file_exists",
                "src_create_time",
                "src_mod_time",
                "src_acc_time",
                "src_metadata_change_time",
                "src_permissions",
                "src_size",
                "block",
                "src_file"]
        else:
            fields = [
                "generated_path",
                "record_filename",  # filename
                "record_type",      # code
                "record_format",    # type
                "record_data",      # value
                "src_create_time",
                "src_mod_time",
                "src_acc_time",
                "src_metadata_change_time",
                "src_permissions",
                "src_size",
                "block",
                "src_file"]

        '''
        Codes that do not always mean that a folder was opened
        Some codes are for informational purposes and may indicate
        the parent was opened not the path reported
        '''
        self.other_info_codes = [
            "Iloc",
            "dilc",
            "cmmt",
            "clip",
            "extn",
            "logS",
            "lg1S",
            "modD",
            "moDD",
            "phyS",
            "ph1S",
            "ptbL",
            "ptbN"
        ]
        '''
        Codes that indicate the finder window changed for an open folder
        or the folders were opened.
        '''
        self.folder_interactions = [
            "dscl",
            "fdsc",
            "vSrn",
            "BKGD",
            "ICVO",
            "LSVO",
            "bwsp",
            "fwi0",
            "fwsw",
            "fwvh",
            "glvp",
            "GRP0",
            "icgo",
            "icsp",
            "icvo",
            "icvp",
            "icvt",
            "info",
            "lssp",
            "lsvC",
            "lsvo",
            "lsvt",
            "lsvp",
            "lsvP",
            "pict",
            "bRsV",
            "pBBk",
            "pBB0",
            "vstl"
        ]
        self.fa_writer = csv.DictWriter(
            all_records_ds_store_report, delimiter="\t", lineterminator="\n",
            fieldnames=fields
        )
        self.fa_writer.writeheader()
        self.fc_writer = csv.DictWriter(
            folder_access_report, delimiter="\t", lineterminator="\n",
            fieldnames=fields
        )
        self.fc_writer.writeheader()
        self.oi_writer = csv.DictWriter(
            other_info_report, delimiter="\t", lineterminator="\n",
            fieldnames=fields
        )
        self.oi_writer.writeheader()
        # Rename fields to match record parsing
        fields[1] = 'filename'
        fields[2] = 'code'
        fields[3] = 'type'
        fields[4] = 'value'


    def write_record(self, record, ds_file, source, stat_dict, opts_check):
        global records_parsed
        #if type(record) == dict:
        if isinstance(record, dict):
            record_dict = record
            record_dict["generated_path"] = f'EMPTY DS_STORE: {ds_file}'
            record_dict["block"] = ''
        else:
            record_dict = record.as_dict()
            block = record_dict[1]
            record_dict = record_dict[0]
            record_dict["block"] = block
            filename = record_dict["filename"]
            record_dict["generated_path"] = self.generate_fullpath(source, ds_file, filename)
            if opts_check:
                abs_path_to_rec_file = os.path.join(os.path.split(ds_file)[0], filename)
                if os.path.lexists(abs_path_to_rec_file):
                    record_dict["file_exists"] = "[EXISTS] NONE"
                    stat_result = self.get_stats(os.lstat(abs_path_to_rec_file))
                    if stat_result:
                        record_dict["file_exists"] = f'{str(stat_result)}'
#                        record_dict["file_exists"] = ''.join(str(stat_result))
                else:
                    record_dict["file_exists"] = "[NOT EXISTS]"
            if record_dict["code"] == "vstl":
                record_dict["value"] = str(self.style_handler(record_dict))
            record_dict["value"] = str(record_dict["value"])
            records_parsed = records_parsed + 1
        record_dict["value"] = record_dict["value"].replace('\r', '').replace('\n', '').replace('\t', '')
        record_dict["generated_path"] = record_dict["generated_path"].replace('\r', '').replace('\n', '').replace('\t', '')
        if os.path.isfile(source):
            source_val = ds_file.replace('\r', '').replace('\n', '').replace('\t', '')
            record_dict["src_file"] = f'{source}, {source_val}'
        else:
            record_dict["src_file"] = ds_file.replace('\r', '').replace('\n', '').replace('\t', '')
        record_dict["filename"] = record_dict["filename"].replace('\r', '').replace('\n', '').replace('\t', '')
        record_dict["src_metadata_change_time"] = stat_dict['src_metadata_change_time']
        record_dict["src_acc_time"] = stat_dict['src_acc_time']
        record_dict["src_mod_time"] = stat_dict['src_mod_time']
        record_dict["src_create_time"] = stat_dict['src_birth_time']
        record_dict["src_size"] = stat_dict['src_size']

        record_dict["src_permissions"] = f'{stat_dict["src_perms"]}, '\
                                         f'User: {str(stat_dict["src_uid"])},'\
                                         f'Group: {str(stat_dict["src_gid"])}'
        if 'Codec' in str(record_dict["type"]):
            record_dict["type"] = f'blob ({record_dict["type"]})'
        check_code = record_dict["code"]
        record_dict["code"] = f'{record_dict["code"]}'\
                              f' ({self.update_descriptor(record_dict)})'
        self.fa_writer.writerow(record_dict)

        if check_code in self.other_info_codes:
            self.oi_writer.writerow(record_dict)
        elif check_code in self.folder_interactions:
            self.fc_writer.writerow(record_dict)

        else:
            print(f'Code not accounted for - {record_dict["code"]}')


    def get_stats(self, stat_result):
        stat_dict = {}
        stat_dict['src_acc_time'] = f'{self.convert_time(stat_result.st_atime)} [UTC]'
        stat_dict['src_mod_time'] = f'{self.convert_time(stat_result.st_mtime)} [UTC]'
        stat_dict['src_perms'] = self.perm_to_text(stat_result.st_mode)
        stat_dict['src_size'] = stat_result.st_size
        stat_dict['src_uid'] = stat_result.st_uid
        stat_dict['src_gid'] = stat_result.st_gid
        if os.name == 'nt':
            stat_dict['src_birth_time'] = f'{self.convert_time(stat_result.st_birthtime)} [UTC]'
            stat_dict['src_metadata_change_time'] = f'{self.convert_time(stat_result.st_ctime)} [UTC]'
        else:
            stat_dict['src_birth_time'] = f'{self.convert_time(stat_result.st_ctime)} [UTC]'
            stat_dict['src_metadata_change_time'] = f'{self.convert_time(stat_result.st_ctime)} [UTC]'
            #stat_dict['src_metadata_change_time'] = ''
        return stat_dict


    def get_stats_image(self, stat_result):
        stat_dict = {}
        stat_dict['src_acc_time'] = f'{self.convert_time(stat_result.atime)} [UTC]'
        stat_dict['src_mod_time'] = f'{self.convert_time(stat_result.mtime)} [UTC]'
        stat_dict['src_perms'] = self.perm_to_text(stat_result.mode)
        stat_dict['src_size'] = stat_result.size
        stat_dict['src_uid'] = stat_result.uid
        stat_dict['src_gid'] = stat_result.gid


        try:
            stat_dict['src_birth_time'] = f'{self.convert_time(stat_result.crtime)} [UTC]'
            stat_dict['src_metadata_change_time'] = f'{self.convert_time(stat_result.ctime)} [UTC]'
        except:
            stat_dict['src_birth_time'] = f'{self.convert_time(stat_result.ctime)} [UTC]'
            stat_dict['src_metadata_change_time'] = ''
        return stat_dict


    def convert_time(self, timestamp):
        return str(datetime.datetime.utcfromtimestamp(timestamp))


    def perm_to_text(self, perm):
        '''
        From https://gist.github.com/beugley/47b4812df0837fc90e783347faee2432
        '''
        perms = {
            "0": "---",
            "1": "--x",
            "2": "-w-",
            "3": "-wx",
            "4": "r--",
            "5": "r-x",
            "6": "rw-",
            "7": "rwx"
            }
        m_perm = perm
        perm = oct(int(perm))
        if len(perm) == 4:
            first = perm[0]
            perm = perm[1:]
        else:
            first = ""

        try:
            outperms = ""
            for p in perm:
                outperms += perms[p]
        except KeyError as e:
            outperms = perm

        if first != "":
            if first == '0':
                pass
            elif first == '1':
                pass
            elif first == '2':
                if outperms[5] == 'x':
                    outperms = f'{outperms[:5]}s{outperms[6:]}'
                else:
                    outperms = f'{outperms[:5]}S{outperms[6:]}'
            elif first == '4':
                if outperms[2] == 'x':
                    outperms = f'{outperms[:2]}s{outperms[3:]}'
                else:
                    outperms = f'{outperms[:2]}S{outperms[3:]}'
            else:
                outperms = perm

        return f"Perms: {str(m_perm)}/-{outperms}"


    def generate_fullpath(self, source, ds_file, record_filename):
        '''
        Generates the full path for the current record
        being parsed from the DS_Store file. The DS_Store does not store the
        full path of a record entry, only the file name is stored.
        The generated full path will be the relative path to the DS_Store being
        parsed plus the file name for the record entry.
        '''
        if os.path.isfile(source):
            ds_store_rel_path = os.path.split(ds_file)[0]
        else:
            ds_store_abs_path = os.path.split(source)[0]
            abs_path_len = len(ds_store_abs_path)
            ds_store_rel_path = os.path.split(ds_file)[0][abs_path_len:]
        generated_path = os.path.join(ds_store_rel_path, record_filename)
        generated_path = generated_path.replace('\r', '').replace('\n', '').replace('\t', '')
        if os.name == 'nt':
            generated_path = generated_path.replace('\\', '/')
        if generated_path[:1] != '/':
            generated_path = f'/{generated_path}'

        return generated_path


    def update_descriptor(self, record):
        types_dict = type_codes
        try:
            code_desc = str(types_dict[record["code"]])
        except:
            code_desc = f'Unknown Code: {(record["code"])}'
        return code_desc


    def style_handler(self, record):
        styles_dict = {
            '\x00\x00\x00\x00': "0x00000000: Null",
            "none": "none: Unselected",
            "icnv": "icnv: Icon View",
            "clmv": "clmv: Column View",
            "Nlsv": "Nlsv: List View",
            "glyv": "glyv: Gallery View",
            "Flwv": "Flwv: CoverFlow View"
            }

        try:
            code_desc = styles_dict[record["value"]]
        except:
            code_desc = f'Unknown Code: {record["value"].decode()}'
        return code_desc


def get_arguments():
    """Get needed options for the cli parser interface"""
    usage = f"""DSStoreParser CLI tool v{__VERSION__}"""
    usage = f"""{usage}\n\nSearch for .DS_Store files in the path provided and parse them."""
    argument_parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(usage)
    )

    argument_parser.add_argument(
        '-s',
        '--source',
        dest='source',
        action="store",
        ###type=commandline_arg,
        required=True,
        help='The source path to search recursively for .DS_Store files to parse. '
    )

    argument_parser.add_argument(
        '-o',
        '--out',
        dest='outdir',
        action="store",
        ###type=commandline_arg,
        required=True,
        help='The destination folder for generated reports.'
    )
    return argument_parser


def main():
    global folder_access_report, other_info_report, all_records_ds_store_report, records_parsed

    arguments = get_arguments()
    options = arguments.parse_args()
    '''
    if os.path.isfile(options.source) and DFVFS_IMPORT is False:
        options.error(IMPORT_ERROR)
    '''
    s_path = []
    s_name = '*.ds_store*'

    opts_source = options.source
    opts_out = options.outdir
    opts_check = False
    timestr = strftime("%Y%m%d-%H%M%S")

    try:
        folder_access_report = open(
            os.path.join(opts_out, f'DS_Store-Folder_Access_Report-{timestr}.tsv'),
            'wb'
            )
        other_info_report = open(
            os.path.join(opts_out, f'DS_Store-Miscellaneous_Info_Report-{timestr}.tsv'),
            'wb'
            )
        all_records_ds_store_report = open(
            os.path.join(opts_out, f'DS_Store-All_Parsed_Report-{timestr}.tsv'),
            'wb'
            )

    except Exception as exp:
        print(f'Unable to proceed. Error creating reports. Exceptions: {exp}')
        sys.exit(0)

    # Accounting for paths ending with \"
    if opts_source[-1:] == '"':
        opts_source = opts_source[:-1]

    record_handler = RecordHandler(opts_check)
    '''
    if os.path.isfile(opts_source):
        scan_path_spec = None
        scanner = source_scanner.SourceScanner()
        scan_context = source_scanner.SourceScannerContext()
        scan_context.OpenSourcePath(opts_source)

        scanner.Scan(
            scan_context,
            scan_path_spec=scan_path_spec
        )

        for file_system_path_spec, file_system_scan_node in scan_context._file_system_scan_nodes.items():
            try:
                location = file_system_path_spec.parent.location
            except:
                location = file_system_path_spec.location
            print "  Processing Volume {}.\n".format(location)

            root_path_spec = path_spec_factory.Factory.NewPathSpec(
                file_system_path_spec.type_indicator,
                parent=file_system_path_spec.parent,
                location="/"
            )

            file_entry = resolver.Resolver.OpenFileEntry(
                root_path_spec
            )
            if file_entry != None:
                directory_recurse(file_system_path_spec, "/", record_handler, opts_source, opts_check)
    '''
    for root, dirnames, filenames in os.walk(opts_source):
        #for filename.lower() in fnmatch.filter(filenames.lower(), s_name):
        for filename in filenames:
            if fnmatch.fnmatch(filename.lower(), s_name):
                ds_file = os.path.join(root, filename)
                file_io = open(ds_file, "rb")
                stat_dict = {}
                stat_dict = record_handler.get_stats(os.lstat(ds_file))
                parse(ds_file, file_io, stat_dict, record_handler, opts_source, opts_check)

    print(f'Records Parsed: {records_parsed}')
    print(f'Reports are located in {options.outdir}')


def directory_recurse(file_system_path_spec, parent_path, record_handler, opts_source, opts_check):
    path_spec = path_spec_factory.Factory.NewPathSpec(
        file_system_path_spec.type_indicator,
        parent=file_system_path_spec.parent,
        location=parent_path
    )
    file_entry = resolver.Resolver.OpenFileEntry(
        path_spec
    )
    if file_entry is not None:
    #if file_entry != None:
        for sub_file_entry in file_entry.sub_file_entries:
            if sub_file_entry.entry_type == 'directory':
                dir_path = os.path.join(parent_path, sub_file_entry.name).replace("\\", "/")
                if dir_path.count('/') == 1:
                    print(f'Searching {dir_path} for .DS_Stores')
                new_path_spec = path_spec_factory.Factory.NewPathSpec(
                    path_spec.type_indicator,
                    parent=path_spec.parent,
                    location=dir_path
                )
                directory_recurse(new_path_spec, dir_path, record_handler, opts_source, opts_check)

            elif sub_file_entry.name == '.DS_Store':
                ds_file = os.path.join(parent_path, sub_file_entry.name).replace("\\", "/")
                file_io = sub_file_entry.GetFileObject()
                stat_dict = {}
                setattr(file_io, 'name', ds_file)
                stats = sub_file_entry.GetStat()

                setattr(stats, 'crtime', sub_file_entry._tsk_file.info.meta.crtime)
                setattr(stats, 'ctime', sub_file_entry._tsk_file.info.meta.ctime)
                setattr(stats, 'mtime', sub_file_entry._tsk_file.info.meta.mtime)
                setattr(stats, 'atime', sub_file_entry._tsk_file.info.meta.atime)
                setattr(stats, 'mode', int(sub_file_entry._tsk_file.info.meta.mode))
                stat_dict = record_handler.get_stats_image(stats)
                parse(ds_file, file_io, stat_dict, record_handler, opts_source, opts_check)
            else:
                continue


def parse(ds_file, file_io, stat_dict, record_handler, source, opts_check):
    '''
     script will update accessed ts for write access volume in macOS
     when it reads contents of the file
    '''
    ds_handler = None
    record = {}
    record['code'] = ''
    record['value'] = ''
    record['type'] = ''
    record['filename'] = ''
    try:
        # Account for empty .DS_Store files
        if stat_dict['src_size'] != 0:
            ds_handler = ds_store_handler.DsStoreHandler(
                file_io,
                ds_file
            )
    # When handler cannot parse ds, print exception as row
    except Exception as exp:
        err_msg = f'ERROR: {exp} for file {ds_file}\n'
        print(err_msg.replace('\n', ''))
    if ds_handler:
        print(f'DS_Store Found: {ds_file}')
        for rec in ds_handler:
            record_handler.write_record(
                rec,
                ds_file,
                source,
                stat_dict,
                opts_check
            )
    elif stat_dict['src_size'] == 0 and os.path.split(ds_file)[1] == '.DS_Store':
        record_handler.write_record(
            record,
            ds_file,
            source,
            stat_dict,
            opts_check
        )
    else:
        pass


#def commandline_arg(bytestring):
#    unicode_string = bytestring
#    return unicode_string


if __name__ == '__main__':
    main()
