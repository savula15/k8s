# -*- coding: utf-8 -*-
import argparse, os, sys, time, subprocess
import threading
from threading import Thread
import ast
from os.path import expanduser
import shutil

class Virtualization(object):

    _instance = None

    def __init__(self, cluster='dev-cluster1', user=None):
        if not user:
            print("Namespac/user param must be specified. Nothing to do further. Exiting...")
            sys.exit(1)
        else:
            self.user = user
        
        self.cluster = cluster
        self.namespace = user
        self.vms = []
        
        self.topology_types = ['node', 'node2node', 'clos-2x3']
        self._clos_types = ['bgp']
        self._node2node_types = ['arp', 'vlan', 'span', 'ndp', 'mac', 'lag', 'dualstack', 'bfd', 'lldp', 'syslog', 'ssh']
        self._node_types = ['dns', 'ntp', 'dhcprelay']
        
        self._all_known_types = self.topology_types + self._clos_types + self._node2node_types + self._node_types

        self.helm_templates = {}

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Virtualization, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def discover_topology(self, topology_name):
        vms = []
        if not topology_name:
            print(" 'topology_name' should not be empty. Nothing to do !!")
            return vms

        self.vmInfo = {"topology": {"name": "", "username": self.user, "cluster": {"name": self.cluster, "vms": []},},}

        if topology_name in self._node2node_types:
            self.vmInfo['topology']['name'] = topology_name
            for i in range(1,3):
                self.vmInfo['topology']['cluster']['vms'].append(topology_name + '-switch{}'.format(i))
        
        elif topology_name in self._node_types:
            self.vmInfo['topology']['name'] = topology_name
            self.vmInfo['topology']['cluster']['vms'].append(topology_name + '-switch1')
        
        elif topology_name in self._clos_types:
            self.vmInfo['topology']['name'] = topology_name
            self.vmInfo['topology']['cluster']['vms'].append(topology_name + '-spine1')
            self.vmInfo['topology']['cluster']['vms'].append(topology_name + '-spine2')
            self.vmInfo['topology']['cluster']['vms'].append(topology_name + '-leaf1')
            self.vmInfo['topology']['cluster']['vms'].append(topology_name + '-leaf2')
            self.vmInfo['topology']['cluster']['vms'].append(topology_name + '-borderleaf1')
        
        elif topology_name in self.topology_types:
            if topology_name == 'node':
                self.vmInfo['topology']['name'] = topology_name
                self.vmInfo['topology']['cluster']['vms'].append('node-' + 'switch1')
            elif topology_name == 'node2node':
                self.vmInfo['topology']['name'] = topology_name
                for i in range(1,3):
                    self.vmInfo['topology']['cluster']['vms'].append('node2node-' + 'switch{}'.format(i))
            elif topology_name == 'clos-2x3':
                self.vmInfo['topology']['name'] = topology_name
                self.vmInfo['topology']['cluster']['vms'].append('clos-2x3-' + 'spine1')
                self.vmInfo['topology']['cluster']['vms'].append('clos-2x3-' + 'spine2')
                self.vmInfo['topology']['cluster']['vms'].append('clos-2x3-' + 'leaf1')
                self.vmInfo['topology']['cluster']['vms'].append('clos-2x3-' + 'leaf2')
                self.vmInfo['topology']['cluster']['vms'].append('clos-2x3-' + 'borderleaf1')

        else:
            print("Specified topology is not yet supported!! It should be one of {}".format(self._all_known_types))
            sys.exit(1)
    
        vms = list(self.vmInfo['topology']['cluster']['vms'])

        return vms

    def deploy(self, topology, topology_type, topology_version='v1.1.0', topology_values='', monolithic=False, cnnos=False, cnnos_version='release', snapl=''):
        if topology_type == "clos-2x3" and topology not in self._clos_types:
            self._clos_types.append(topology)
            self._all_known_types.append(topology)
        elif topology_type == "node2node" and topology not in self._node2node_types:
            self._node2node_types.append(topology)
            self._all_known_types.append(topology)
        elif topology_type == "node" and topology not in self._node_types:
            self._node_types.append(topology)
            self._all_known_types.append(topology)

        if snapl == '':
            if not monolithic:
                snapl_image = "--set-string topology-builder.dhcpOptions.privateOptions[0].value='http://192.168.100.73/onie-installer-x86_64'"
            else:
                snapl_image = ''
        else:
            snapl_image = "--set-string topology-builder.dhcpOptions.privateOptions[0].value='{}'".format(snapl)
        
        deployed = False
        vms = []
        if topology_type and topology_type not in ['node', 'node2node', 'clos-2x3']:
            print('Requested topology type {} is not yet supported. Exiting...'.format(topology_type))
            sys.exit(1)
        elif not topology_type:
            print("Topology deployment was requested. But, 'topology_type' was not specified.")
            sys.exit(1)

        print("Deploying '{}' topology of type '{}' !".format(topology, topology_type))
        if monolithic:
            deployed, vms = self.deploy_and_load_charts(deploy=True,
                                                        name=topology,
                                                        topology_type=topology_type,
                                                        topology_version=topology_version,
                                                        topology_values=topology_values,
                                                        monolithic=True,
                                                        install=False)
        elif cnnos:
            if snapl_image != '':
                snapl_ver = snapl_image
            
            if cnnos_version:
                charts_ver = cnnos_version
            else:
                print('cnnos_version that will be installed is: {}'.format(cnnos_version))
            
            deployed, vms = self.deploy_and_load_charts(deploy=True,
                                                        name=topology, 
                                                        topology_type=topology_type, 
                                                        topology_version=topology_version, 
                                                        topology_values=topology_values, 
                                                        cnnos_version=charts_ver, 
                                                        monolithic=False, 
                                                        snapl=snapl_ver,
                                                        install=True)
        
        elif snapl_image != '':
            deployed, vms = self.deploy_and_load_charts(deploy=True,
                                                        name=topology, 
                                                        topology_type=topology_type, 
                                                        topology_version=topology_version, 
                                                        topology_values=topology_values, 
                                                        monolithic=False,
                                                        snapl=snapl_image,
                                                        install=False)
        
        else:
            print('Neither of monolithic install, cnnos charts install or snapl install methods was specified')

        if deployed and vms:
            print("Successfully deployed topology")
            # cmd = "kubectl get cm {}-topology --output json |  jq -r '.data | ."README.MD"' ".format(topology)
            # import pdb;pdb.set_trace()
            # res, output = self.execute_command(cmd)
            # if res:
            #     print(output)
        else:
            print("Topology deployment was failed !!!. Re-try it again..")
        
        return deployed, vms

    def teardown(self, topology, topology_type, topology_version='v1.1.0', topology_values='', monolithic=False, snapl=''):
        deleted = False

        if topology_type == "clos-2x3" and topology not in self._clos_types:
            self._clos_types.append(topology)
            self._all_known_types.append(topology)
        elif topology_type == "node2node" and topology not in self._node2node_types:
            self._node2node_types.append(topology)
            self._all_known_types.append(topology)
        elif topology_type == "node" and topology not in self._node_types:
            self._node_types.append(topology)
            self._all_known_types.append(topology)

        if snapl == '':
            if not monolithic:
                snapl_image = "--set-string topology-builder.dhcpOptions.privateOptions[0].value='http://192.168.100.73/onie-installer-x86_64'"
            else:
                snapl_image = ''
        else:
            snapl_image = "--set-string topology-builder.dhcpOptions.privateOptions[0].value='{}'".format(snapl)

        if topology:
            print("Deleting '{}' topology of type '{}'...".format(topology, topology_type))
            deleted = self.deploy_and_load_charts(teardown=True,
                                                  name=topology, 
                                                  topology_type=topology_type, 
                                                  topology_version=topology_version, 
                                                  topology_values=topology_values, 
                                                  monolithic=monolithic,
                                                  snapl=snapl_image)
        else:
            print("Topology deletion was requested. But, 'topology' name was not specified.")

        return deleted
        
    def reload_charts(self, topology, topology_type, cnnos_version='release'):
        installed = False

        if topology_type == "clos-2x3" and topology not in self._clos_types:
            self._clos_types.append(topology)
            self._all_known_types.append(topology)
        elif topology_type == "node2node" and topology not in self._node2node_types:
            self._node2node_types.append(topology)
            self._all_known_types.append(topology)
        elif topology_type == "node" and topology not in self._node_types:
            self._node_types.append(topology)
            self._all_known_types.append(topology)

        print("Reloading charts on all VM's in '{}' ".format(topology))
        installed = self.deploy_and_load_charts(name=topology, cnnos_version=cnnos_version, reload_charts=True)
        
        return installed

    def execute_command(self, cmd, ignore_errors=True):

        # print("Executing {}".format(cmd))
        test_result = False
        exec_cmd = subprocess.Popen([cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
        (out, err) = exec_cmd.communicate()
        if exec_cmd.returncode != 0 and err != '':
            # print(msg = "KUBECTL Command Error : \n{}".format(str(err)))
            test_result = False
            return test_result, str(err)
        elif exec_cmd.returncode == 0 and "Warning: Permanently added" in err:
            # print(msg = "KUBECTL Command Error : \n{}".format(str(err)))
            test_result = True
            return test_result, str(err)
        elif exec_cmd.returncode == 0 and "succeeded" in err:
            test_result = True
            return test_result, str(err)
        elif exec_cmd.returncode == 0 and "was scheduled to stop" in err:
            test_result = True
            return test_result, str(err)
        else:
            # print(msg = "KUBECTL Command Output: \n{}".format(str(out)))
            test_result = True
            return test_result, str(out)

    def update_kubeconfig(self, vmname, service_ip, ssh_port=None, api_port=None, update=True, cleanup=False, skip_copy=False, namedpath=False, recreate=False, verbose=False):
        net_result = True
        HOME = expanduser("~")
        CACHE=HOME + "/.snapl/"

        path = ""
        kubectlParamsDir = os.path.join(os.getenv("SR_CODE_BASE", "./"), "snaproute/src/test", "kubectlParams")

        USER="root"
        PASSWORD=''

        KUBEPATH="/mnt/state/kubernetes/admin.conf"

        service_ip = service_ip

        if ssh_port:
            ssh_port = ssh_port
        else:
            ssh_port=22

        api_port = api_port

        node_path = ""
        if namedpath:
            node_path = kubectlParamsDir
        else:
            node_path = CACHE + '{}-{}'.format(service_ip, ssh_port)

        path = node_path

        if not os.path.exists(path):
            os.makedirs(path)
        elif recreate:
            try:
                if verbose:
                    print('Directory {} exists. Deleting it and will be re-created'.format(path))
                shutil.rmtree(path)
                time.sleep(2)
            except OSError, e:
                print('Directory {} does not exists. It will be created'.format(path))
            os.makedirs(path)
        elif verbose:
            print('Directory {} exists.'.format(path))
            
        if not namedpath:
            TARGET=path + '/admin.conf'
        else:
            TARGET=path + '/' + vmname

        if cleanup:
            ret, out = self.execute_command("rm -rf {}".format(TARGET))
            if not ret:
                print("Could not delete file at {} due to {}. Its safe to ignore".format(TARGET, out))
        else:
            if not skip_copy:
                if PASSWORD:
                    command = "sshpass -p {} scp -P {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{}:{} {}".format(PASSWORD, ssh_port, USER, service_ip, KUBEPATH, TARGET)
                else:
                    command = "sshpass -p '' scp -P {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{}:{} {}".format(ssh_port, USER, service_ip, KUBEPATH, TARGET)

                try:
                    res, output = self.execute_command(command)
                    if not res:
                        print("Downloading the admin conf failed for {} due to {}".format(service_ip, output))
                    elif verbose:
                        print("Successfully downloaded admin conf for {}:{}".format(vmname, service_ip))
                except:
                    print("Could not scp admin.conf from {}".format(service_ip))
                    net_result = False

            if not os.path.exists(TARGET):
                print('admin.conf profile does not exists at {}'.format(TARGET))
                net_result = False

            else:
                try:
                    self.execute_command("KUBECONFIG={} kubectl config delete-cluster {}".format(TARGET, 'localhost'))
                    self.execute_command("KUBECONFIG={} kubectl config set-cluster {} --server=https://{}:{} --insecure-skip-tls-verify=true".format(TARGET, 'localhost', service_ip, api_port))
                    if verbose:
                        print("Updated kubeconfig profile at {}".format(TARGET))
                except:
                    print("Could not update kubeconfig profile at {}".format(TARGET))
                    net_result   = False
        
        CLUSTER_NAME=vmname
        CONTEXT_NAME='admin@{}'.format(CLUSTER_NAME)
        CREDENTIALS_NAME=CONTEXT_NAME
        DEFAULT_KUBECONFIG = HOME + '/.kube/config'
        KUBE_DIR = HOME + '/.kube/'

        if net_result and update:
            try:
                exists = os.path.isfile("{}/config.lock".format(KUBE_DIR))
                if exists:
                    self.execute_command("rm {}/config.lock".format(KUBE_DIR))
    
                res, out = self.execute_command("KUBECONFIG={} kubectl config delete-cluster {}".format(DEFAULT_KUBECONFIG, vmname))
                res, out = self.execute_command("KUBECONFIG={} kubectl config unset users.admin@{}".format(DEFAULT_KUBECONFIG, vmname))
                res, out = self.execute_command("KUBECONFIG={} kubectl config delete-context admin@{}".format(DEFAULT_KUBECONFIG, vmname))
                
                if cleanup:
                    if verbose:
                        print("Removed cluster/credentials/context in kubeconfig {}".format(DEFAULT_KUBECONFIG))
                else:
                    self.execute_command("KUBECONFIG={} kubectl config set-cluster {} --server=https://{}:{} --insecure-skip-tls-verify=true".format(DEFAULT_KUBECONFIG, vmname, service_ip, api_port))
                    self.execute_command("KUBECONFIG={} kubectl config set-credentials admin@{}".format(DEFAULT_KUBECONFIG, vmname))

                    cert_data, key_data = self._get_user_cert_data(target=TARGET)
                    self.execute_command("KUBECONFIG={} kubectl config set users.'admin@{}'.client-certificate-data {}".format(DEFAULT_KUBECONFIG, vmname, cert_data))

                    self.execute_command("KUBECONFIG={} kubectl config set users.'admin@{}'.client-key-data {}".format(DEFAULT_KUBECONFIG, vmname, key_data))

                    self.execute_command("KUBECONFIG={} kubectl config set-context admin@{} \
                        --cluster {} \
                        --user admin@{}".format(DEFAULT_KUBECONFIG, vmname, vmname, vmname))

                    if verbose:
                        print("Updated cluster/credentials/context in kubeconfig: {}".format(DEFAULT_KUBECONFIG))
                        print("kubectl config use-context admin@{}".format(vmname))

            except:
                print('Could not create/update context for {} in default kube config'.format(vmname))
                net_result = False

        return net_result

    def _get_user_cert_data(self, target):
        res, data = self.execute_command("KUBECONFIG={} kubectl config view --raw -o json | jq -r ['.users[] | [.user][] | to_entries[]]'".format(target))
        output = ast.literal_eval(data)

        for item in output:
            if "client-certificate-data" in item.values():
                cert_data = item['value']
            elif "client-key-data" in item.values():
                key_data = item['value']

        return cert_data, key_data

    def change_context(self, vm):

        service_ip, ssh_port, api_port = self.get_kube_ports(vmname=vm)

        # print('Updating kubeconfig for CN-NOS {}'.format(vm))
        retval = self.update_kubeconfig(vmname=vm, service_ip=service_ip, ssh_port=ssh_port, api_port=api_port)

        return retval

    def delete_context(self, vm):

        service_ip, ssh_port, api_port = self.get_kube_ports(vmname=vm)

        print('Deleting context for {}'.format(vm))
        retval = self.update_kubeconfig(vmname=vm, service_ip=service_ip, ssh_port=ssh_port, api_port=api_port, cleanup=True)

        return retval

    def load_charts(self, topology_name, vms=[], cnnos_version='release'):
        threads = []

        if cnnos_version == 'release':
            cnnos_version = cnnos_version
            chart_type = 'release'
        elif cnnos_version == 'develop':
            cnnos_version = cnnos_version
            chart_type = 'develop'
        else:
            cnnos_version = cnnos_version
            if 'rel' in cnnos_version:
                chart_type = 'release'
            elif 'D' in cnnos_version:
                chart_type = 'develop'

        if not vms:
            if topology_name in self._all_known_types:
                vms = self.discover_topology(topology_name=topology_name)
            else:
                print("Unknown topology name is specified. '{}' might not have been deployed!!!".format(topology_name))
        else:
            vms = vms

        if vms:
            for vm in vms:
                # t1 = threading.Thread(name=None, target=self.install_charts, args=(vm,cnnos_version,))
                t1 = threading.Thread(name=None, target=self.install_cnnos_charts_from_repo, args=(vm, cnnos_version, chart_type,))
                threads.append(t1)
                t1.start()
                time.sleep(2)

            for t in threads: t.join()
        else:
            print("No target nodes specified to load charts")

    def install_cnnos_charts_from_repo(self, vm, cnnos_version, chart_type="release"):
        chart_file = 'cnnos' + '-' + cnnos_version + '.tgz'
        
        if not os.path.exists(chart_file):
            ret, chart_name = self.fetch_chart_from_repo(name=chart_type, chart='cnnos', version=cnnos_version)
        else:
            ret = True
            chart_name = chart_file
        
        if ret:
            print("Loading charts version '{}' on: {}".format(cnnos_version, vm))

            retval = self.change_context(vm=vm)

            if retval:
                res = self.purge_charts(vmname=vm)
                if res == 0 or res == 1:
                    print('Installing new charts on {}'.format(vm))
                    rt = 1
                    rt = os.system('bash -c "' + 'helm upgrade --install cn-nos {} --kube-context=admin@{}" '.format(chart_name, vm))
                    if rt == 0:
                        print('And waiting for charts to load on {}'.format(vm))
                elif res == -1:
                    print('Could not connect to {} and hence could not install charts'.format(vm))

    def purge_charts(self, vmname):
        res, output = self.execute_command("helm list --kube-context=admin@{} --output json".format(vmname))

        if "Error" in output:
            print('Following error occured while checking charts state: {}'.format(str(output)))
            return -1

        elif res and output:
            print('Found cn-nos charts. Deleting charts on {}'.format(vmname))
            os.system('bash -c "' + 'helm delete cn-nos --purge --kube-context=admin@{}" '.format(vmname))
            print('And waiting for charts to be deleted on {}'.format(vmname))
            time.sleep(60)
            return 0

        else:
            print('CN-NOS does not exists on VM. Nothing to purge')
            return 1

    def get_all_duts(self, topology, namespace=None):
        if not namespace:
            namespace = self.namespace

        jq_cmd = "['.items[] | { name:.metadata.name,ip:.status.loadBalancer.ingress[].ip }']"
        cmd = 'kubectl --namespace {} get services -l app={} -o json | jq -r {}'.format(namespace, topology, jq_cmd)
        res, output = self.execute_command(cmd)

        duts = []
        if res:
            duts = ast.literal_eval(output)
        else:
            print("Could not get services info")

        return duts

    def get_kube_ports(self, vmname):
        service_ip, ssh_port, api_port = "", "", ""

        cmd = "kubectl --namespace {} get services {} -o json".format(self.namespace, vmname)
        res, output = self.execute_command(cmd)
        if  res:
            data = ast.literal_eval(output)

            service_type=data['spec']['type']
            if service_type == "LoadBalancer":
                cluster_ip=data['spec']['clusterIP']
                service_ip=data['status']['loadBalancer']['ingress'][0]['ip']
                ports=data['spec']['ports']
                for port in ports:
                    if port['name'] == 'kube-api':
                        api_port = port['port']
                    elif port['name'] == 'ssh':
                        ssh_port=port['port']
        return service_ip, ssh_port, api_port

    def get_kubeconfigfile(self, vm, namedpath=False, update=False):
        HOME = expanduser("~")
        CACHE=HOME + "/.snapl/"
        node_path = ""

        kubectlParamsDir = os.path.join(os.getenv("SR_CODE_BASE", "./"), "snaproute/src/test", "kubectlParams")

        cmd = "kubectl --namespace {} get services {} -o json".format(self.namespace, vm)
        res, output = self.execute_command(cmd)
        data = ast.literal_eval(output)

        service_type=data['spec']['type']

        if service_type == "LoadBalancer":
            cluster_ip=data['spec']['clusterIP']
            service_ip=data['status']['loadBalancer']['ingress'][0]['ip']
            ports=data['spec']['ports']
            for port in ports:
                if port['name'] == 'kube-api':
                    api_port = port['port']
                elif port['name'] == 'ssh':
                    ssh_port=port['port']

        if namedpath:
            node_path = os.path.join(kubectlParamsDir, vm)
        else:
            node_path = CACHE + '{}-{}'.format(service_ip, ssh_port) + '/admin.conf'
        TARGET_PATH = node_path

        res = self.update_kubeconfig(vmname=vm, service_ip=service_ip, ssh_port=ssh_port, api_port=api_port, namedpath=namedpath, update=update)

        if res:
            return res, TARGET_PATH
        else:
            print('Could not update kubeconfig')

    def verify_pod_status(self, topology_name, vms=[], verbose=False):

        if not vms:
            if topology_name in self._all_known_types:
                vms = self.discover_topology(topology_name=topology_name)
            else:
                print("Unknown topology name is specified. '{}' might not have been deployed!!!".format(topology_name))
        else:
            vms = vms
        
        done = False
        timeout = 60 * len(vms) + 180
        waited = 0
        pod_states = {}
        while not done:
            pods = {}
            for vm in vms:
                vm_ready = True
                try:
                    # print("Getting pods status on: {} ".format(vm))
                    retval = self.change_context(vm=vm)

                    jq_cmd = "['.items | sort_by(.spec.nodeName)[] | [.metadata.name, .status.phase]']"

                    cmd = 'kubectl get pods -o json --context=admin@{} | jq -r {}'.format(vm, jq_cmd)
                    test_pass, output = self.execute_command(cmd)
                    
                    if test_pass:
                        data = ast.literal_eval(output)

                    for item in data:
                        pods.update({item[0]: item[1]})

                    for pod, state in pods.items():
                        if state != 'Running' and state != 'Succeeded':
                            if verbose:
                                print("{} is not in running state.".format(pod))
                            vm_ready = False
                        elif state == 'Succeeded' and 'ztp' not in pod:
                            if verbose:
                                print("{} is not in running state".format(pod))
                            vm_ready = False
                    
                    pod_states[vm] = vm_ready
                    if not vm_ready:
                        print("{} is not ready yet. Waiting for few seconds before checking again".format(vm))
                        time.sleep(60)
                        waited += 60
                    print("Current pods state on {}: {} ".format(vm, pods))
                except:
                    print("Could not get pod status on {}".format(vm))
                    pod_states[vm] = False
            if waited > timeout or all(pod_states.values()):
                done = True

        if all(pod_states.values()):
            print("CN-NOS deployement is successfull !!!")
            if verbose:
                print("Waiting for few seconds to ensure all CRD's are registered")
            time.sleep(60)
        else:
            print("CN-NOS deployment has failed for nodes: {} !!!".format([k for k, v in  pod_states.items()  if not v]))

        return all(pod_states.values())

    def _get_pod_state(self, pod_name):
        ret, temp = self.execute_command("kubectl get po {} -o json | jq -r '.status.phase'".format(pod_name))

        topology_pod_state = ''
        if ret:
            topology_pod_state = temp.strip()
        
        return topology_pod_state

    def _get_containers_state(self, pod_name):
        ret, output = self.execute_command("kubectl get po {} -o json | jq -r '.status.containerStatuses[] | .ready'".format(pod_name))

        container_states = {}
        if ret:
            container_states = output.strip().split('\n')

        return container_states

    def _are_containers_ready(self, pod_name):
        ready_state = True
        container_states = self._get_containers_state(pod_name=pod_name)
        if container_states:
            for container in container_states:
                if not bool(str(container).capitalize()):
                    ready_state = False
            print('Current state of containers in {} is: {}'.format(pod_name, container_states))
        else:
            print('Could not get container states in {}'.format(pod_name))
            ready_state = False
        
        return ready_state

    def _verify_deployment_state(self, name, teardown=False):
        net_result = True

        res, output = self.execute_command("kubectl get pods -o json --context=dev-cluster1 | jq -r ['.items[] | .metadata.name']")
        pods = []
        if res:
            data = ast.literal_eval(output)
            for temp_pod in data:
                if name in temp_pod:
                    pods.append(temp_pod)
        
        topology_pod = ''
        for topo_pod in pods:
            if 'topology' in topo_pod:
                topology_pod = topo_pod
                pods.remove(topo_pod)
        
        topology_pod_state = ''
        if topology_pod:
            wait = 60
            done = False
            ready = False
            while not done:
                if wait <= 0:
                    done = True
                topology_pod_state = self._get_pod_state(pod_name=topology_pod)
                if topology_pod_state and topology_pod_state == 'Running':
                    done = True
                    ready = True
                else:
                    wait -= 1
            if ready:
                print('Topology pod {} is ready and waiting for few seconds before checking vm pods state'.format(topology_pod))
                time.sleep(45)
            else:
                print('Topology pod {} is not ready even after waiting 60 seconds !!!'.format(topology_pod))
                net_result = False
        else:
            print('Could not get topology pod state')
            topology_pod_state = ''
            net_result = False
        
        pods_ready = []
        if topology_pod_state == 'Running':
            for pod in pods:
                pod_ready = False
                pod_state = self._get_pod_state(pod_name=pod)
                if pod_state and pod_state == 'Running':
                    pod_ready = self._are_containers_ready(pod_name=pod)
                    if not pod_ready:
                        time.sleep(60)
                        pod_ready = self._are_containers_ready(pod_name=pod)
                    pods_ready.append(pod_ready)
                else:
                    print('Could not get pod state for {}'.format(pod))
                    pods_ready.append(pod_ready)
            if pods_ready:
                net_result = all(pods_ready)
        else:
            print("One or more pods/containers in '{}' topology are not ready yet!!!".format(name))
            net_result = False

        return net_result

    def fetch_chart_from_repo(self, name, chart, version, url=''):
        rt4 = 1
        rt = 1
        if not url:
            if name == 'release':
                rt = os.system('bash -c "' + 'helm repo add release https://192.168.100.145/chartrepo/qa-nightly-release" ')
            elif name == 'develop':
                rt = os.system('bash -c "' + 'helm repo add develop https://192.168.100.145/chartrepo/qa-nightly" ')
            else:
                rt = os.system('bash -c "' + 'helm repo add {} https://192.168.100.145/chartrepo/{}" '.format(name, name))
        else:
            rt = os.system('bash -c "' + 'helm repo add {} {}" '.format(name, url))
        # rt = os.system('bash -c "' + 'helm repo add vm-topologies https://192.168.100.145/chartrepo/vm-topologies" ')
        rt2 = 1
        if rt == 0:
            rt2 = os.system('bash -c "' + 'helm repo update" ')
            rt3 = 1
            if rt2 == 0:
                rt3 = os.system('bash -c "' + 'helm fetch {}/{} --version={}" '.format(name, chart, version))
                chart_name = chart + '-' + version + '.tgz'
                if rt3 == 0:
                    if not os.path.exists(chart_name):
                        print("Failed to fetch {}".format(chart_name))
                    else:
                        print("Successfully fetched {}".format(chart_name))
                        rt4 = 0
            else:
                print("Failed to update {}".format(name))
        else:
            print("Failed to add repo {}".format(name))

        return rt4 == 0, chart_name

    def deploy_topology(self, name, topology_type='node', version="v1.1.0", topology_values='', monolithic=False, snapl='', teardown=False):
        net_result = True
        
        ret, topology_chart_name = self.fetch_chart_from_repo(name='vm-topologies', chart=topology_type, version=version, url="https://192.168.100.145/chartrepo/vm-topologies")

        helm_template_cmd = ''
        if ret:
            if name in self._all_known_types:
                if teardown:
                    if name in self.helm_templates and self.helm_templates[name] != '':
                        helm_template_cmd = self.helm_templates[name]
                    else:
                        if not monolithic:
                            if topology_values != '':
                                helm_template_cmd = "helm template -n {} {} --values {} --set-string topology-builder.dhcpOptions.privateOptions[0].option=114 {}".format(name, topology_chart_name, topology_values, snapl)
                            else:
                                helm_template_cmd = "helm template -n {} {} --set-string topology-builder.dhcpOptions.privateOptions[0].option=114 {}".format(name, topology_chart_name, snapl)
                        else:
                            if topology_values != '':
                                helm_template_cmd = "helm template -n {} {} --values {}".format(name, topology_chart_name, topology_values)
                            else:
                                helm_template_cmd = "helm template -n {} {}".format(name, topology_chart_name)
                                
                    if helm_template_cmd:
                        print("Deleting topology '{}' ".format(name))
                        vms = self.discover_topology(topology_name=name)

                        ret = self._stop_all_vms_in_topology(vms=vms)
                        if ret:
                            time.sleep(45) # Change this to more determinstic way of verifying
                            rt = 1
                            rt = os.system('bash -c "' + '{} | kubectl delete -f -" '.format(helm_template_cmd))
                            if rt == 0:
                                print('And waiting for topology resources to be deleted')
                                time.sleep(30)
                                print("'{}' topology resources are successfully deleted !!".format(name))
                                print("Removing context for all vms")
                                for vm in vms:
                                    ret = self.delete_context(vm=vm)
                            else:
                                print('Deletion of tepology seems to have failed. Try to delete manually')
                            if not ret:
                                net_result = False
                else:
                    if not monolithic:
                        if topology_values != '':
                            helm_template_cmd = "helm template -n {} {} --values {} --set-string topology-builder.dhcpOptions.privateOptions[0].option=114 {}".format(name, topology_chart_name, topology_values, snapl)
                            os.system('bash -c "' + '{} | kubectl create -f -" '.format(helm_template_cmd))
                        else:
                            helm_template_cmd = "helm template -n {} {} --set-string topology-builder.dhcpOptions.privateOptions[0].option=114 {}".format(name, topology_chart_name, snapl)
                            os.system('bash -c "' + '{} | kubectl create -f -" '.format(helm_template_cmd))
                    else:
                        if topology_values != '':
                            helm_template_cmd = "helm template -n {} {} --values {}".format(name, topology_chart_name, topology_values)
                            os.system('bash -c "' + '{} | kubectl create -f -" '.format(helm_template_cmd))
                        else:
                            helm_template_cmd = "helm template -n {} {}".format(name, topology_chart_name)
                            os.system('bash -c "' + '{} | kubectl create -f -" '.format(helm_template_cmd))
                    self.helm_templates[name] = helm_template_cmd
                    print('And waiting for topology to be deployed')
                    time.sleep(15)

                    deployment_state = self._verify_deployment_state(name=name)
                    if not deployment_state:
                        print("Deployment '{}' has failed. One or more pods are not ready")
                        net_result = False
                    else:
                        print("Successfully deployed '{}' and proceeding to check if apiserver is ready!!".format(name))
            else:
                print('Either the specifid topology is not yet supported or invalid one requsted.')
                net_result = False
            if net_result:
                if not teardown:
                    vms = self.discover_topology(topology_name=name)
                else:
                    print('Removing chart file {}'.format(topology_chart_name))
                    os.remove(topology_chart_name)
                    time.sleep(2)
                    return net_result, []
        else:
            net_result = False

        return net_result, vms
    
    def _setup_kubecontext_and_load_charts_on_vms(self, topology_name='', vms=[], cnnos_version="release"):

        if not vms:
            print("No vms specified. Will be loading charts on all vms in '{}' topology".format(topology_name))
        
        self.load_charts(topology_name=topology_name, vms=vms, cnnos_version=cnnos_version)

    def is_kube_apiserver_ready(self, vm):
        ready = False
        service_ip, ssh_port, api_port = self.get_kube_ports(vmname=vm)
        ret, output = self.execute_command("nc -zv {} {}".format(service_ip, api_port))
        
        if ret and len(output) > 0:
            ready = 'succeeded' in str(output)
      
        return ready

    def is_tiller_ready(self, vm):
        ret, output = self.execute_command("kubectl get po --namespace kube-system -l name==tiller --context=admin@{} -o json | jq -r '.items[] | .status.phase'".format(vm))

        tiller_state = ''
        if ret:
            tiller_state = output.strip()
        
        if tiller_state and tiller_state == 'Running':
            return True
        elif tiller_state and tiller_state != 'Running':
            return False
        else:
            return False

    def deploy_and_load_charts(self, name, topology_type='node', topology_version="v1.1.0", topology_values='', cnnos_version="release", monolithic=False, snapl='', deploy=False, teardown=False, install=False, reload_charts=False):
        final_status = True
        
        ret = False
        vms = []
        if deploy:
            if monolithic:
                ret, vms = self.deploy_topology(name=name,
                                                topology_type=topology_type,
                                                version=topology_version,
                                                topology_values=topology_values,
                                                monolithic=True)
            elif install or snapl != '':
                ret, vms = self.deploy_topology(name=name,
                                                topology_type=topology_type,
                                                version=topology_version,
                                                topology_values=topology_values,
                                                monolithic=False,
                                                snapl=snapl)
        elif teardown:
            ret, vms = self.deploy_topology(teardown=True,
                                            name=name, 
                                            topology_type=topology_type,
                                            version=topology_version,
                                            topology_values=topology_values,
                                            monolithic=monolithic,
                                            snapl=snapl)
            if not ret and vms:
                print("Topology teardown seems to have failed")
                return False
            else:
                return True
        
        elif reload_charts:
            vms = self.discover_topology(topology_name=name)
            ret = [True if vms else False][0]

        if ret and vms:
            pod_states = {}
            done = False
            timeout = 120 * len(vms) + 180
            waited = 0
            api_ready_vms = []
            api_not_ready_vms = []
            while not done:
                for vm in vms:
                    ready = False
                    ready = self.is_kube_apiserver_ready(vm=vm)
                    if not ready:
                        print("Api server on '{}' is not ready yet. Waiting for few seconds before checking it again..".format(vm))
                        time.sleep(60)
                        waited += 60
                    pod_states[vm] = ready
                if waited > timeout or all(pod_states.values()):
                    done = True
            api_ready_vms =  [k for k, v in pod_states.items() if v]
            api_not_ready_vms = [k for k, v in pod_states.items() if not v]
            if done and api_ready_vms:
                vms = api_ready_vms
                kube_ready_vms = []
                kube_not_ready_vms = []
                vms_ready  = {}
                for vm in vms:
                    retval = self.change_context(vm=vm)
                    vms_ready[vm]  =  retval
                kube_ready_vms = [k for k, v in vms_ready.items() if v]
                kube_not_ready_vms = [k for k, v in vms_ready.items() if not v]
                if kube_ready_vms:
                    vms = kube_ready_vms
                    
                    print("Api server is ready on vms '{}' and checking if tiller is ready".format(vms))
                    tiller_states = {}
                    done = False
                    timeout = 60 * len(vms)  + 60
                    waited = 0
                    tiller_ready_vms = []
                    tiller_not_ready_vms = []
                    while not done:
                        for vm in vms:
                            ready = False
                            ready = self.is_tiller_ready(vm=vm)
                            if not ready:
                                print("Tiller on '{}' is not ready yet. Waiting for few seconds before checking it again..".format(vm))
                                time.sleep(60)
                                waited += 60
                            tiller_states[vm] = ready
                        if waited > timeout or all(tiller_states.values()):
                            done = True
                    tiller_ready_vms =  [k for k, v in tiller_states.items() if v]
                    tiller_not_ready_vms = [k for k, v in tiller_states.items() if not v]
                    if done and tiller_ready_vms:
                        vms = tiller_ready_vms
                        print("Api server and tiller are ready on vms '{}'".format(vms))
                        if install:
                            if not monolithic:
                                print("Non monolithic installation is requested. CNNOS will be installed via charts")
                                self._setup_kubecontext_and_load_charts_on_vms(topology_name=name, vms=vms, cnnos_version=cnnos_version)
                            final_status = self.verify_pod_status(topology_name=name, vms=vms)
                        elif not install and monolithic:
                            print("Topology is deployed using monolithic image and CNNOS charts were deployed. Proceeding to check pod status")
                            final_status = self.verify_pod_status(topology_name=name, vms=vms)
                        elif reload_charts:
                            print("Charts re-installation is requested.")
                            self._setup_kubecontext_and_load_charts_on_vms(topology_name=name, vms=vms, cnnos_version=cnnos_version)
                            final_status = self.verify_pod_status(topology_name=name, vms=vms)
                        else:
                            print("Topology is deployed but neither monolithic image nor cnnos charts install was requested. VM's are ready to deploy CN-NOS")
                    if tiller_not_ready_vms:
                        print("Tiller is not ready on vms '{}'. Not installing CN-NOS charts !!".format(tiller_not_ready_vms))
                        final_status = False

                if kube_not_ready_vms:
                    print("Could not setup kube context for vms '{}'. Manually install CN-NOS charts on them !!".format(kube_not_ready_vms))
                    final_status = False
            if api_not_ready_vms:
                print("Api server is not ready yet on vms '{}' ".format(api_not_ready_vms))
                final_status = False

        else:
            print(" '{}' topology was not deployed completely. Hence, CN-NOS charts install was skipped!!".format(name))
            final_status = False
        
        return final_status, vms

    def _stop_all_vms_in_topology(self, vms=[], verbose=False):
        duts = []
        if vms:
            duts = vms
        else:
            print('No vm targets were specified')
            return False
        
        if duts:
            stopped = []
            net_result = True
            for dut in duts:
                ret, output = self.execute_command("virtctl stop {}".format(dut))
                if ret:
                    stopped.append(dut)
                    if verbose:
                        print("Successfully stopped {}".format(dut))
                else:
                    print("Could not stop {} due to {}. Ensure to stop all vms before topology deletion".format(dut, output))
                    net_result = False
        
            if net_result:
                print("Successfully stopped following vms and waiting for vm pods to be deleted! : {}".format(duts))
            
            return net_result
    


        