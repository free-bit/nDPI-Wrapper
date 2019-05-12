#!/usr/bin/env python2

import sys
import os

import grpc
# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '/home/vagrant/tutorials/utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(argv):
# Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(argv[2])

# Initiate switch connection.
# This code is adapted from p4lang/tutorials (https://github.com/p4lang/tutorials).
    try:
        # Create a switch connection object for the switch;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt file.
        switch_connection = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1', # XXX: What does this name correspond to?
            address='192.168.6.99:50051', # TODO: Parametrize the IP/port
            device_id=0)

        switch_connection.MasterArbitrationUpdate()

        switch_connection.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=argv[1])
    except grpc.RpcError as e:
        printGrpcError(e)
        return

if __name__ == "__main__":
    main(sys.argv)
