#!/usr/bin/env python
"""Copyright 2020 Cisco Systems
All rights reserved.
Remarks: QoS class-map search function included.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

 * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.

The contents of this file are licensed under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
"""

"""
Wraps gNMI RPCs with a reasonably useful CLI for interacting with network elements.
Supports Capabilities, Subscribe, Get, and Set.

Command parsing sourced from this wonderful blog by Chase Seibert
https://chase-seibert.github.io/blog/2014/03/21/python-multilevel-argparse.html
"""
import json
import logging
import argparse
from getpass import getpass
from google.protobuf import json_format, text_format
from . import ClientBuilder, proto, __version__
from google.protobuf.internal import enum_type_wrapper
import sys
import re

MAX_MESSAGE_LENGTH = 10000 * 1024 ** 2

def main():
    # Using a map so we don't have function overlap e.g. set()
    rpc_map = {
        "capabilities": gnmi_capabilities,
        "subscribe": gnmi_subscribe,
        "get": gnmi_get,
        "set": gnmi_set,
    }
    parser = argparse.ArgumentParser(
        description="gNMI CLI demonstrating cisco_gnmi library usage.",
        usage="""
cisco-gnmi <rpc> [<args>]

Version {version}
** QoS class-map search version **
Supported RPCs:
{supported_rpcs}
cisco-gnmi capabilities 127.0.0.1:57500
cisco-gnmi get 127.0.0.1:57500 -xpath /interfaces/interface/state/counters
cisco-gnmi set 127.0.0.1:57500 -update_json_config newconfig.json
cisco-gnmi subscribe 127.0.0.1:57500 -xpath /interfaces/interface/state/counters -dump_file intfcounters.proto.txt

See <rpc> --help for RPC options.
    """.format(
            version=__version__, supported_rpcs="\n".join(sorted(list(rpc_map.keys())))
        ),
    )
    parser.add_argument("rpc", help="gNMI RPC to perform against network element.")
    args = parser.parse_args(sys.argv[1:2])
    if args.rpc not in rpc_map.keys():
        logging.error(
            "%s not in supported RPCs: %s!", args.rpc, ", ".join(rpc_map.keys())
        )
        parser.print_help()
        exit(1)
    try:
        rpc_map[args.rpc]()
    except Exception:
        logging.exception("Error during usage!")
        exit(1)


def gnmi_capabilities():
    parser = argparse.ArgumentParser(
        description="Performs Capabilities RPC against network element."
    )
    args = __common_args_handler(parser)
    client = __gen_client(args)
    capability_response = client.capabilities()
    logging.info(__format_message(capability_response))


def gnmi_subscribe():
    """Performs a streaming Subscribe against network element.
    """
    parser = argparse.ArgumentParser(
        description="Performs Subscribe RPC against network element."
    )
    parser.add_argument(
        "-xpath", help="XPath to subscribe to.", type=str, action="append"
    )
    parser.add_argument(
        "-interval",
        help="Sample interval in seconds for Subscription. Defaults to 10.",
        type=int,
        default=10,
    )
    parser.add_argument(
        "-mode",
        help="SubscriptionMode for Subscription. Defaults to SAMPLE.",
        default="SAMPLE",
        choices=proto.gnmi_pb2.SubscriptionMode.keys(),
    )
    parser.add_argument(
        "-req_mode",
        help="SubscriptionList.Mode mode for Subscriptions. Defaults to STREAM.",
        default="STREAM",
        choices=proto.gnmi_pb2.SubscriptionList.Mode.keys(),
    )
    parser.add_argument(
        "-suppress_redundant",
        help="Suppress redundant information in Subscription.",
        action="store_true",
    )
    parser.add_argument(
        "-heartbeat_interval", help="Heartbeat interval in seconds.", type=int
    )
    parser.add_argument(
        "-dump_file",
        help="Filename to dump to. Defaults to stdout.",
        type=str,
        default="stdout",
    )
    parser.add_argument(
        "-dump_json",
        help="Dump as JSON instead of textual protos.",
        action="store_true",
    )
    parser.add_argument(
        "-sync_stop", help="Stop on sync_response.", action="store_true"
    )
    parser.add_argument(
        "-sync_start",
        help="Start processing messages after sync_response.",
        action="store_true",
    )
    parser.add_argument(
        "-encoding",
        help="gNMI Encoding. Defaults to whatever Client wrapper prefers.",
        type=str,
        choices=proto.gnmi_pb2.Encoding.keys(),
    )
    
    ## QoS argument #######################
    parser.add_argument(
        "-cmap", 
        help="Allow class-map search and it lists respective QoS stats.",
        type=str,
    )
    ## hardware-module argument ###########
    parser.add_argument(
        "-hwmod",
        help="This lists hw alerts (name, category, description).",
        action="store_true",
    )
    
    
    ########################################
    
    args = __common_args_handler(parser)
    # Set default XPath outside of argparse due to default being persistent in argparse.
    if not args.xpath:
        args.xpath = ["/interfaces/interface/state/counters"]
    client = __gen_client(args)
    # Take care not to override options unnecessarily.
    kwargs = {}
    if args.encoding:
        kwargs["encoding"] = args.encoding
    if args.interval:
        kwargs["sample_interval"] = args.interval * int(1e9)
    if args.mode:
        kwargs["sub_mode"] = args.mode
    if args.req_mode:
        kwargs["request_mode"] = args.req_mode
    if args.suppress_redundant:
        kwargs["suppress_redundant"] = args.suppress_redundant
    if args.heartbeat_interval:
        kwargs["heartbeat_interval"] = args.heartbeat_interval * int(1e9)
    
    try:
        logging.debug(
            "Dumping responses to %s as %s ...",
            args.dump_file,
            "JSON" if args.dump_json else "textual proto",
        )
        logging.debug("Subscribing to:\n%s", "\n".join(args.xpath))
        synced = False
        for subscribe_response in client.subscribe_xpaths(args.xpath, **kwargs):
            logging.debug("SubscribeResponse received.")
            if subscribe_response.sync_response:
                logging.debug("sync_response received.")
                print("****** SYNC *********")
                if args.sync_stop:
                    logging.warning("Stopping on sync_response.")
                    break
                synced = True
            if not synced and args.sync_start:
                continue
            formatted_message = __format_message(subscribe_response)
            if args.dump_file == "stdout":
                if args.hwmod:
                   print(gnmi_hwmodule(formatted_message))
                   break
                
                #Call QoS function to search class-map                
                if not args.cmap:
                    logging.info(formatted_message)
                else:
                    print(gnmi_qos(formatted_message, args.cmap))
                    break
            else:
                with open(args.dump_file, "a") as dump_fd:
                    dump_fd.write(formatted_message)
                    dump_fd.write("** Terminating program...")
                    dump_fd.close()
                    break
            break       
    except KeyboardInterrupt:
        logging.warning("Stopping on interrupt.")
    except Exception:
        logging.exception("Stopping due to exception!")
###########################################################################
#  Search class-map and list statistics                                   #
###########################################################################
def gnmi_qos(content, classmap_name):
    regex = r'json_ietf_val\: (".+")'
    r = []
   
    for json_str in re.findall(regex, content):
        data = json.loads(json.loads(json_str))
        r.append(data)
    
    result = {}

    c = 0
    for if_data in r[0]:  
                
        diffserv_info = if_data.get('diffserv-info')
        if diffserv_info:
            if_data_result = {}
            for classifier_stats in diffserv_info:
                if_data_result['direction'] = classifier_stats['direction']
                if_data_result['policy-name'] = classifier_stats['policy-name']
                classmap_stats = {}
                # Search through the statistics
                for stats in classifier_stats['diffserv-target-classifier-stats']:
                    if stats['classifier-entry-name'] == classmap_name:
                        classmap_stats[classmap_name] = {
                            'drop-bytes': stats['queuing-stats']['drop-bytes'],
                            'drop-bytes': stats['queuing-stats']['drop-pkts'],
                            'parent-path': stats['parent-path']
                            # add more stats here
                        }
                if_data_result['classifier-stats'] = classmap_stats

            if if_data_result:
                result[if_data['name']] = if_data_result

    return result
#######  
def gnmi_hwmodule(content):
    """This will retrieve values such as temperature, FAN, voltage  """
    regex = r'json_ietf_val\: (".+")'
    r = []
   
    for json_str in re.findall(regex, content):
        data = json.loads(json.loads(json_str))
        r.append(data)
    
    alarms = []
    for alarm in r[0]['device-hardware'].get('device-alarm', []):
        alarms.append((
            alarm['alarm-category'],
            alarm['alarm-description'],
            alarm['alarm-name']
        ))
    return alarms
   
###########    
def gnmi_get():
    """Provides Get RPC usage. Assumes JSON or JSON_IETF style configurations.
    """
    parser = argparse.ArgumentParser(
        description="Performs Get RPC against network element."
    )
    parser.add_argument("-xpath", help="XPaths to Get.", type=str, action="append")
    parser.add_argument(
        "-encoding",
        help="gNMI Encoding.",
        type=str,
        choices=proto.gnmi_pb2.Encoding.keys(),
    )
    parser.add_argument(
        "-data_type",
        help="gNMI GetRequest DataType",
        type=str,
        choices=enum_type_wrapper.EnumTypeWrapper(
            proto.gnmi_pb2._GETREQUEST_DATATYPE
        ).keys(),
    )
    parser.add_argument(
        "-dump_json",
        help="Dump as JSON instead of textual protos.",
        action="store_true",
    )
    args = __common_args_handler(parser)
    # Set default XPath outside of argparse due to default being persistent in argparse.
    if not args.xpath:
        args.xpath = ["/interfaces/interface/state/counters"]
    client = __gen_client(args)
    kwargs = {}
    if args.encoding:
        kwargs["encoding"] = args.encoding
    if args.data_type:
        kwargs["data_type"] = args.data_type
    get_response = client.get_xpaths(args.xpath, **kwargs)
    logging.info(__format_message(get_response))


def gnmi_set():
    """Provides Set RPC usage. Assumes JSON or JSON_IETF style configurations.
    Applies update/replace operations, and then delete operations.
    TODO: This is the least well understood/implemented. Need to validate if there is an OOO for update/replace/delete.
    """
    parser = argparse.ArgumentParser(
        description="Performs Set RPC against network element."
    )
    parser.add_argument(
        "-update_json_config", help="JSON-modeled config to apply as an update."
    )
    parser.add_argument(
        "-replace_json_config", help="JSON-modeled config to apply as a replace."
    )
    parser.add_argument(
        "-delete_xpath", help="XPaths to delete.", type=str, action="append"
    )
    parser.add_argument(
        "-no_ietf", help="JSON is not IETF conformant.", action="store_true"
    )
    parser.add_argument(
        "-dump_json",
        help="Dump as JSON instead of textual protos.",
        action="store_true",
    )
    args = __common_args_handler(parser)
    if not any([args.update_json_config, args.replace_json_config, args.delete_xpath]):
        raise Exception("Must specify update, replace, or delete parameters!")

    def load_json_file(filename):
        config = None
        with open(filename, "r") as config_fd:
            config = json.load(config_fd)
        return json.dumps(config)

    if args.update_json_config or args.replace_json_config:
        kwargs = {}
        if args.update_json_config:
            kwargs["update_json_configs"] = load_json_file(args.update_json_config)
        if args.replace_json_config:
            kwargs["replace_json_configs"] = load_json_file(args.replace_json_config)
        if args.no_ietf:
            kwargs["ietf"] = False
        client = __gen_client(args)
        set_response = client.set_json(**kwargs)
        logging.info(__format_message(set_response))
    if args.delete_xpath:
        if getattr(client, "delete_xpaths", None) is not None:
            delete_response = client.delete_xpaths(args.xpath)
            logging.info(__format_message(delete_response))
        else:
            raise Exception(
                "Convenience delete_xpaths is not supported in the client library!"
            )


def __gen_client(args):
    
           
    builder = ClientBuilder(args.netloc)
    builder.set_os(args.os)
    builder.set_call_authentication(args.username, args.password)
    ###
    builder.set_channel_option('grpc.max_send_message_length', MAX_MESSAGE_LENGTH)
    builder.set_channel_option('grpc.max_receive_message_length', MAX_MESSAGE_LENGTH)
    ###
    
    if args.insecure:
        builder._set_insecure()
    elif not any([args.root_certificates, args.private_key, args.certificate_chain]):
        builder.set_secure_from_target()
    else:
        builder.set_secure_from_file(
            args.root_certificates, args.private_key, args.certificate_chain
        )
    if args.ssl_target_override:
        builder.set_ssl_target_override(args.ssl_target_override)
    elif args.auto_ssl_target_override:
        builder.set_ssl_target_override()
    return builder.construct()


def __format_message(message, as_json=False):
    formatted_message = None
    if as_json:
        formatted_message = json_format.MessageToJson(message, sort_keys=True)
    else:
        formatted_message = text_format.MessageToString(message)
    return formatted_message


def __common_args_handler(parser):
    """Ideally would be a decorator."""
    parser.add_argument("netloc", help="<host>:<port>", type=str)
    parser.add_argument(
        "-os",
        help="OS wrapper to utilize. Defaults to IOS XR.",
        type=str,
        default="IOS XR",
        choices=list(ClientBuilder.os_class_map.keys()),
    )
    parser.add_argument(
        "-root_certificates", help="Root certificates for secure connection."
    )
    parser.add_argument("-private_key", help="Private key for secure connection.")
    parser.add_argument(
        "-certificate_chain", help="Certificate chain for secure connection."
    )
    parser.add_argument("-ssl_target_override", help="gRPC SSL target override option.")
    parser.add_argument(
        "-auto_ssl_target_override",
        help="Use root_certificates first CN as grpc.ssl_target_name_override.",
        action="store_true",
    )
    parser.add_argument("-debug", help="Print debug messages.", action="store_true")
    parser.add_argument("-insecure", help=argparse.SUPPRESS, action="store_true")
     
    args = parser.parse_args(sys.argv[2:])
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    args.username = input("Username: ")
    args.password = getpass()
    return args


if __name__ == "__main__":
    main()
