import os
import json
import re
from networkx.drawing.nx_agraph import graphviz_layout
import matplotlib.pyplot as plt
import networkx as nx
import subprocess
import pickle

class BaseAnalysis(object):
    def __init__(self, scan_folder, crypto_lib_desc, verbose=0):
        self.scan_folder = scan_folder
        self.crypto_lib_desc = crypto_lib_desc
        self.verbose = verbose
        self.crypto_lib = dict()
        self.elf_files = []

        self.min_num_crypto_apis = 100000

        for idx, lib in enumerate(self.crypto_lib_desc):
            regex = re.compile(lib['elfname'])
            self.crypto_lib_desc[idx]['regex'] = regex
            if len(self.crypto_lib_desc[idx]['APIs']) < self.min_num_crypto_apis:
                self.min_num_crypto_apis = len(self.crypto_lib_desc[idx]['APIs'])

    def gen_report(self, output_folder=None):
        pass
    
    def write_report(self, report, report_name, output_folder):
        if output_folder is not None:
            with open(os.path.join(output_folder, report_name), "w+") as f:
                f.write(json.dumps(report, indent=4))


    def draw_graph(self, graph, show=True):
        mapping = {node: os.path.basename(node) for node in graph.nodes()}
        color_map = []
        new_graph = nx.relabel_nodes(graph, mapping)
        crypto_lib_base = [os.path.basename(x) for x in self.crypto_lib]
        elf_files_base = [os.path.basename(x) for x in self.elf_files]
        for node in new_graph:
            if node in crypto_lib_base:
                color_map.append('orange')
            elif node in elf_files_base:
                color_map.append('skyblue')
            else:
                color_map.append('yellow')

        pos = graphviz_layout(new_graph, prog='dot', args="-Grankdir=LR")
        plt.clf()

        nx.draw(new_graph, pos=pos, with_labels=True, node_color=color_map, node_size=2000, arrows=True, font_size=8)
        if show:
            plt.show()


    def _file_type(self, f):
        if f in self.crypto_lib:
            return "root"
        elif f in self.elf_files:
            return "leaf"
        else: 
            return "interm"
        
    

    # lightweight method for checking ELF file based on 4-byte magic number
    def _is_elf(self, file_path):
        # ELF magic number
        elf_magic = b'\x7fELF'
        
        try:
            # Open the file in binary mode
            with open(file_path, 'rb') as f:
                # Read the first 4 bytes
                header = f.read(4)
                
                # Check if the first 4 bytes match the ELF magic number
                return (header == elf_magic)

        except IOError:
            # Error occurred while opening or reading the file
            return False
        
    

    def get_api_exposed(self, elf):
        command = ['readelf', '--dyn-syms', '--wide', elf]

        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                return None

            output_lines = result.stdout.split('\n')
            output_lines = output_lines[4:]
            #if len(output_lines) < self.min_num_crypto_apis:
            #    return None
            symbol_names = []

            for _, line in enumerate(output_lines):
                if not line:
                    continue
                sline = line.split()

                # Example:
                #       9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND execv@GLIBC_2.2.5 (8)
                #     611: 0000000000034730    27 FUNC    GLOBAL DEFAULT   15 ssh_get_serverbanner@@LIBSSH_4_5_0
                if len(sline) < 8 or sline[6] == 'UND' or sline[3] != 'FUNC':
                    continue
                symbol_name = sline[7].split('@')[0]
                symbol_names.append(symbol_name)
            
            return symbol_names
        except FileNotFoundError as e:
            print(f"Command not found: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    
    
    # readelf and get UND for Ndx
    def get_api_calls(self, elf):
        command = ['readelf', '--dyn-syms', '--wide', elf]

        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                return []

            output_lines = result.stdout.split('\n')
            output_lines = output_lines[4:]
            #if len(output_lines) < self.min_num_crypto_apis:
            #    return []
            
            symbol_names = []

            for _, line in enumerate(output_lines):
                if not line:
                    continue
                sline = line.split()

                # Example:
                #       9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND execv@GLIBC_2.2.5 (8)
                #     611: 0000000000034730    27 FUNC    GLOBAL DEFAULT   15 ssh_get_serverbanner@@LIBSSH_4_5_0
                if len(sline) < 8 or sline[6] != 'UND' or sline[3] != 'FUNC':
                    continue
                symbol_name = sline[7].split('@')[0]
                symbol_names.append(symbol_name)
            
            return symbol_names
        except FileNotFoundError as e:
            print(f"Command not found: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

        return None