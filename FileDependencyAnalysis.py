import subprocess
import os
import networkx as nx
from networkx.exception import NetworkXNoPath
from networkx.drawing.nx_agraph import graphviz_layout
from elftools.elf.elffile import ELFFile
import matplotlib.pyplot as plt
import time
from BaseAnalysis import BaseAnalysis
import pickle

class FileDependencyAnalysis(BaseAnalysis):
    def __init__(self, scan_folder, crypto_lib_desc, verbose=0):
        super().__init__(scan_folder,crypto_lib_desc,verbose)

        self.sw_dep = nx.DiGraph()
        self.vuln_elf = []

        self.dep_graph = nx.DiGraph()

    
    def gen_report(self, output_folder=None):

        self.analyze()

        # Dependency-vulnerable graph shows all ELF files that have (in)direct dependencies (i.e., dynamically link) with quantum-vulnerable cryptolibs
        # self.vuln_elf contains all leaves + intermediate + roots that depend on identified cryptolib
        # So we just have to take intersection between self.vuln_elf and self.elf_files to get leaves that are quantum-vulnerable
        report = list()
        for libpath, _ in self.crypto_lib.items():
            report.append({"elf": libpath, "path": [libpath], "type": self._file_type(libpath)})

        for elf in self.elf_files:
            if elf not in self.vuln_elf:
                continue
            for libpath, _ in self.crypto_lib.items():
                try:
                    if elf in report:
                        print("WARNING:", elf, "calls multiple quantum-vulnerable crypto libraries. We don't support detecting multiple libs yet.")
                    shortest_path = nx.shortest_path(self.dep_graph, source=libpath, target=elf)
                    shortest_path.reverse()
                    report.append({"elf": elf, "shortest path": shortest_path, "type": self._file_type(elf)})
                except NetworkXNoPath:
                    pass

        full_report = {}
        metadata = {"num_apps_before": len(self.elf_files), "num_total_before": len(self.sw_dep.nodes), 
                    "num_apps_after": len([x for x in (set(self.dep_graph.nodes) & set(self.elf_files))]), 
                    "num_total_after": len(self.dep_graph.nodes)}
        full_report['metadata'] = metadata
        full_report['QV_apps'] = [x for x in (set(self.dep_graph.nodes) & set(self.elf_files))]
        full_report["report"] =  report

        if output_folder is not None:
            self.write_report(full_report, "dependency.txt", output_folder)
            self.draw_graph(self.dep_graph, show=False)
            plt.savefig(os.path.join(output_folder, "dependency.png"), format="PNG")
            pickle.dump(self, open(os.path.join(output_folder, "dependency.pickle"), 'wb'))

        return full_report

    def analyze(self):
        self._get_all_elf()
        self._gen_sw_dep_graph()

        # remove nodes without dependencies
        self.sw_dep.remove_nodes_from(list(nx.isolates(self.sw_dep)))

        descendants = self._get_nodes_from_crypto_lib(self.sw_dep)

        self.vuln_elf = list(descendants) # & set(self.elf_files))
        self.dep_graph = nx.DiGraph(self.sw_dep.subgraph(descendants))
    
    def _get_nodes_from_crypto_lib(self, graph):
        # Get all nodes reachable from identified elf cryptolib

        descendants = set()
        for node in self.crypto_lib.keys():
            descendants |= nx.descendants(graph, node)
            descendants.add(node)
        return descendants

    
    def _gen_sw_dep_graph(self):
        self.checked = set()
        for idx, elf in enumerate(self.elf_files):
            if self.verbose and idx%100 == 0:
                print(idx, "/", len(self.elf_files), "checked")
            self._gen_sw_dep_graph_helper(elf, elf, 0, 5)
            #if idx == 200:
            #    break

    def _gen_sw_dep_graph_helper(self, root, elf, cur_depth=0, max_depth=5):
        if cur_depth >= max_depth:
            return
        
        # already checked, we skip
        if elf in self.checked:
            return
        
        self.checked.add(elf)
        self.sw_dep.add_node(elf)

        lib = self._is_crypto_lib(elf)
        if lib is not None:
            self.crypto_lib[elf] = lib

        # recursively checking its dynamic libraries
        shared_lib_paths = self._list_direct_dep(elf)
        if shared_lib_paths is not None:
            for p in shared_lib_paths:
                self.sw_dep.add_edge(p, elf) # Library points to main exec
                self._gen_sw_dep_graph_helper(root, p, cur_depth+1, max_depth)


    # Find whether elf corresponds to crypto lib; if so, which one.
    def _is_crypto_lib(self, elf):
        syms = self.get_api_exposed(elf)
        if syms is None:
            return None
        elf_name = os.path.basename(elf)
        for lib in self.crypto_lib_desc:
            if lib['regex'].match(elf_name):
                num_intersec = len(set(lib['APIs']) & set(syms))
                num_total = len(set(lib['APIs']))
                #print('Found:', elf, num_intersec, num_total)
                if num_intersec/num_total > .8:
                    return lib
        return None

    def _get_all_elf(self):

        for root, _, files in os.walk(self.scan_folder):
            for file in files:
                file_path = os.path.join(root,file)
                if self._is_elf(file_path):
                    self.elf_files.append(os.path.join(root, file))

        if self.verbose:
            print("Folder:", self.scan_folder, "; # elf files:", len(self.elf_files))


    # readelf -a executable_path | grep NEEDED
    # Output the name of shared lib
    def direct_dep(self, executable_path):
        command = ['readelf', '-d', executable_path]
        libs = []

        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                return None

            output_lines = result.stdout.split('\n')

            for line in output_lines:
                if "NEEDED" in line:
                    parts = line.strip().split()
                    libs.append(parts[4][1:-1])
            
            return libs
        except FileNotFoundError as e:
            print(f"Command not found: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    # Basically direct_dep but we return full path instead of filenames
    def _list_direct_dep(self, executable_path):
        dd = self.direct_dep(executable_path)
        if not dd:
            return None
        
        # From name of shared lib, we have to get the full path
        # ldd gives us a full path (but it doesnt give us which shared lib is a direct dependecy)
        
        command = ['ldd', executable_path]
        libs = []

        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                return None

            output_lines = result.stdout.split('\n')

            for line in output_lines:
                parts = line.strip().split()
                # Only consider the one with "=>", pointing to the full path
                if len(parts) >= 3 and '=>' in parts:
                    lib_path = parts[2]
                    if any(d in lib_path for d in dd): 
                        libs.append(lib_path)

            return libs
        except FileNotFoundError as e:
            print(f"Command not found: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")


    def get_filenames_from_paths(paths):
        return [os.path.basename(p) for p in paths]

    

if __name__ == "__main__":
    import time
    import sys
    from crypto_desc import CRYPTO_LIB
    import cProfile, io, pstats

    start = time.time()
    #scan_folder = '/home/oak/Git/PQDetector/openssl'
    crypto_lib_desc = CRYPTO_LIB

    args = sys.argv[1:]

    if len(args) == 0:
        output_dir = 'out-coreutils'
        scan_folder = '/home/oak/Git/PQDetector/cryptolibs/'
        scan_folder = '/home/oak/Git/openssl/oak'
    else:
        output_dir = args[0]
        scan_folder = args[1]

    os.makedirs(output_dir, exist_ok=True) 

    analysis = FileDependencyAnalysis(scan_folder, crypto_lib_desc, verbose=1)

    pr = cProfile.Profile()
    pr.enable()

    analysis.gen_report(output_dir)

    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumtime')
    ps.print_stats()

    with open(os.path.join(output_dir, 'dependency.prof'), 'w+') as f:
        f.write(s.getvalue())