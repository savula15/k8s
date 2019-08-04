#! /Users/sankar/.virtualenv/venv27/bin/python2.7
import os, sys
import argparse

from virtualization import Virtualization

def add_args(parser):
 
    parser.add_argument('--teardown',
                        required=False,
                        action='store_true',
                        help="Teardown a topology. WARNING: Deletes all related resources")

    parser.add_argument('--topology',
                        required=True,
                        action='store',
                        help="Name of topology that should be deployed")

    parser.add_argument('--topology_type',
                        required=True,
                        action='store',
                        help="Type of topology that should be deployed. MUST be one of [node, node2node, clos-2x3]")

    parser.add_argument('--topology_version',
                        required=False,
                        action='store',
                        default='v1.1.0',
                        help="Version of topology that should be deployed. Default v1.1.0")
    
    parser.add_argument('--topology_values',
                        required=False,
                        action='store',
                        default='',
                        help="Path to custom topology values file")

    parser.add_argument('-c', '--cluster',
                        required=False,
                        action='store',
                        default='dev-cluster1',
                        help='cluster or host ip/name')

    parser.add_argument('-u', '--user',
                        required=True,
                        action='store',
                        help='Your user name alias')

    parser.add_argument('--monolithic',
                        required=False,
                        action='store_true',
                        help='flag to indicate if the image will be monolithic. True if switch is specified')
    
    parser.add_argument('--snapl',
                        action='store',
                        default='',
                        help='url or symlink which points to snapl image that will be used to bootstrap cnnos vm')
    
    parser.add_argument('--cnnos',
                        required=False,
                        action='store_true',
                        help='flag to indicate if the cnnos charts shoudl be installed. True if switch is specified')

    parser.add_argument('--cnnos_version',
                        required=False,
                        action='store',
                        default='release',
                        help="version of the cnnos charts that shoudl be installed on VM's")

    parser.add_argument('--cnnos_reload_charts',
                        required=False,
                        action='store_true',
                        help="Reload charts using the cnnos_version speficied. True if switch is specified")

def process(args):
        
    # import pdb;pdb.set_trace()
   
    vmobj = Virtualization(cluster=args.cluster, user=args.user)

    if args.teardown:
        deleted = vmobj.teardown(topology=args.topology,
                                 topology_type=args.topology_type,
                                 topology_version=args.topology_version,
                                 topology_values=args.topology_values,
                                 monolithic=args.monolithic,
                                 snapl=args.snapl)
        return deleted

    if args.cnnos_reload_charts:
        installed = vmobj.reload_charts(topology=args.topology,
                                        topology_type=args.topology_type,
                                        cnnos_version=args.cnnos_version)

        return installed

    if args.monolithic:
        deployed, vms = vmobj.deploy(topology=args.topology,
                                     topology_type=args.topology_type,
                                     topology_version=args.topology_version,
                                     topology_values=args.topology_values,
                                     monolithic=True)
    elif args.cnnos:
        deployed, vms = vmobj.deploy(topology=args.topology,
                                     topology_type=args.topology_type,
                                     topology_version=args.topology_version,
                                     topology_values=args.topology_values,
                                     cnnos=args.cnnos,
                                     cnnos_version=args.cnnos_version,
                                     snapl=args.snapl)
    else:
        deployed, vms = vmobj.deploy(topology=args.topology, 
                                     topology_type=args.topology_type, 
                                     topology_version=args.topology_version, 
                                     topology_values=args.topology_values,
                                     snapl=args.snapl)

    return deployed

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Arguments for deploying VM's")
    add_args(parser)
    
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    process(args)
