#!/usr/bin/env python

"""
Submit one or more reports from local files (txt, pdf, eml, csv, json)
"""
from __future__ import print_function

import argparse
import email
import os
import time

from trustar import TruStar


def process_eml(source_file):
    """
    Parses the content of a '.eml' file
    :param source_file: the '.eml' filename
    :return: the content of the email
    """
    if source_file.endswith('.eml'):
        f = open(source_file, 'r')
        content = f.read()
        current_email = email.message_from_string(content)
        txt = ""
        if current_email.is_multipart():
            txt = build_text_from_payload(current_email.get_payload())
        else:
            txt = current_email.get_payload()
    else:
        raise ValueError('UNSUPPORTED FILE EXTENSION')
    return txt


def build_text_from_payload(payloads, result=""):
    """
    Walks through the nodes of the email tree object and returns the content of the email.
    :param payloads: the tree nodes
    :param result: the content of the email
    :return: the content of the email
    """
    if type(payloads) is list:
        for payload in payloads:
            if type(payload.get_payload()) is str:
                result += payload.get_payload()
            else:
                result += build_text_from_payload(payload.get_payload(), result)
    else:
        result += payloads.get_payload()
    return result


def process_date_from_email(source_file):
    """
    Returns the received date for '.eml' source files.
    :param source_file: the '.eml' filename 
    :return: the received date of the email
    """
    if source_file.endswith('.eml'):
        f = open(source_file, 'r')
        content = f.read()
        current_email = email.message_from_string(content)
        headers = current_email._headers
        date = ""
        for current_tuple in headers:
            if current_tuple[0] == 'Date':
                date = current_tuple[1]
    else:
        raise ValueError('UNSUPPORTED FILE EXTENSION')
    return date


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=(
                                         'Submit one or more reports from local files (txt, pdf, docx, etc) '
                                         'in a directory\n\n'
                                         'Example:\n'
                                         'python bulk_upload.py ./sample_reports'))
    parser.add_argument('dir', help='Path containing report files')
    parser.add_argument('-i', '--ignore', dest='ignore', action='store_true',
                        help='Ignore history and resubmit already procesed files')

    args = parser.parse_args()
    source_report_dir = args.dir

    ts = TruStar(config_role="trustar")
    token = ts.get_token()

    # process all files in directory
    print("Processing and submitting each source file in %s as a TruSTAR Incident Report" % source_report_dir)

    processed_files = set()

    processed_files_file = os.path.join(source_report_dir, "processed_files.log")
    if os.path.isfile(processed_files_file) and not args.ignore:
        processed_files = set(line.strip() for line in open(processed_files_file))

    with open(processed_files_file, 'a', 0) as pf:
        for (dirpath, dirnames, filenames) in os.walk(source_report_dir):
            for source_file in filenames:
                if source_file in processed_files:
                    continue

                print("Processing source file %s " % source_file)
                try:
                    path = os.path.join(source_report_dir, source_file)
                    if path.endswith('.eml'):
                        report_body_txt = process_eml(path)
                        email_date = process_date_from_email(path)

                        response_json = ts.submit_report(token,
                                                         report_body_txt,
                                                         source_file,
                                                         email_date,
                                                         enclave=True)
                    else:
                        report_body_txt = ts.process_file(path)
                        response_json = ts.submit_report(token, report_body_txt, source_file, enclave=True)

                    # response_json = ts.submit_report(token, report_body_txt, "COMMUNITY: " + file)
                    report_id = response_json['reportId']

                    print("SUCCESSFULLY SUBMITTED REPORT, TRUSTAR REPORT as Incident Report ID %s" % report_id)
                    pf.write("%s\n" % source_file)

                    # if 'reportIndicators' in response_json:
                    #     print("Extracted the following indicators: {}".format(response_json['reportIndicators']))
                    # else:
                    #     print("No indicators returned from  report id {0}".format(report_id))
                    #
                    # # if 'correlatedIndicators' in response_json:
                    #     print(
                    #         "Extracted the following correlated indicators: {}".format(
                    #             response_json['correlatedIndicators']))
                    # else:
                    #     print("No correlatedIndicators found in report id {0}".format(report_id))

                except Exception as e:
                    print("Problem with file %s, exception: %s " % (source_file, e))
                    continue

                time.sleep(2)


if __name__ == '__main__':
    main()
