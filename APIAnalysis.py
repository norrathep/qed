import os
import pickle
import matplotlib.pyplot as plt
from BaseAnalysis import BaseAnalysis
from FileDependencyAnalysis import FileDependencyAnalysis
import networkx as nx
from networkx.exception import NetworkXNoPath

class APIAnalysis(BaseAnalysis):

    def __init__(self, fdAnalaysis, verbose=0):
        if isinstance(fdAnalaysis, str):
            fdAnalaysis = pickle.load(open(fdAnalaysis,'rb'))

        if not isinstance(fdAnalaysis, FileDependencyAnalysis):
            raise Exception('Sth is wrong')
        
        super().__init__(fdAnalaysis.scan_folder, fdAnalaysis.crypto_lib_desc, verbose)

        self.dep_graph = fdAnalaysis.dep_graph

        self.crypto_lib = fdAnalaysis.crypto_lib
        self.elf_files = fdAnalaysis.elf_files
        self.api_graph = nx.DiGraph()

        # root nodes dont have used apis
        self.used_apis = dict()

        # leaf nodes dont have exposed apis
        self.exposed_apis = dict()

    def gen_report(self, output_folder=None):
        
        self.analyze()
        return self._gen_report(output_folder)
    
    def analyze(self):
        edge_attrs = self._get_edge_api_attributes()
        self.api_graph = self.dep_graph.copy()
        nx.set_edge_attributes(self.api_graph, edge_attrs)

        g = self.api_graph.copy()

        # remove all edges that have no APIs
        for edge in g.edges:
            if len(g[edge[0]][edge[1]]['APIs']) == 0:
                self.api_graph.remove_edge(edge[0], edge[1])

        g.clear()
        g = self.api_graph.copy()

        # Remove all nodes that have no path to cryptolib
        for node in g.nodes:
            path = False
            for libpath, lib in self.crypto_lib.items():
                if nx.has_path(self.api_graph, source=libpath, target=node):
                    path = True 
                    break
            
            if not path:
                self.api_graph.remove_node(node)
        #print(nx.get_edge_attributes(self.api_graph, 'APIs'))
    
    def _gen_report(self, output_folder):

        report = list()

        for libpath, _ in self.crypto_lib.items():
            report.append({"elf": libpath, "api": [], "path": [libpath], "type": self._file_type(libpath)})

        for elf in self.elf_files:
            if elf not in self.api_graph.nodes:
                continue
            for libpath, _ in self.crypto_lib.items():
                try:
                    #shortest_path = nx.shortest_path(self.api_graph, source=libpath, target=elf)
                    # TODO: return longest path instead??
                    path = nx.shortest_path(self.api_graph, source=libpath, target=elf)
                    path.reverse()
                    cryptolib = path[-1]
                    cryptolib_successor = path[-2]
                    quantum_vuln_apis = self.api_graph[cryptolib][cryptolib_successor]['APIs']
                    report.append({"elf": elf, "api": sorted(list(quantum_vuln_apis)), "path": path, "type": self._file_type(elf)})
                except NetworkXNoPath:
                    pass

        full_report = {}
        metadata = {"num_apps_before": len([x for x in (set(self.dep_graph.nodes) & set(self.elf_files))]), 
                    "num_total_before": len(self.dep_graph.nodes), 
                    "num_apps_after": len([x for x in (set(self.api_graph.nodes) & set(self.elf_files))]), 
                    "num_total_after": len(self.api_graph.nodes)
                    }
        full_report['metadata'] = metadata
        full_report['QV_apps'] = [x for x in (set(self.api_graph.nodes) & set(self.elf_files))]
        full_report["report"] = report

        if output_folder is not None:
            self.write_report(full_report, "api.txt", output_folder)
            self.draw_graph(self.api_graph, show=False)
            plt.savefig(os.path.join(output_folder, "api.png"), format="PNG")
            pickle.dump(self, open(os.path.join(output_folder, "api.pickle"), 'wb'))
        return full_report

    
    def _remove_node(self, node):
        self.api_graph.remove_node(node)
        if node in self.used_apis:
            del self.used_apis[node]
        if node in self.exposed_apis:
            del self.exposed_apis[node]

    def _get_edge_api_attributes(self):
        edge_attrs = dict()
        # root => cryptolib, leaf => apps
        # edge contains a set of parent's APIs used by child. Other parents APIs are removed from this edge
        for edge in self.dep_graph.edges:
            parent = edge[0]
            child = edge[1]

            if parent not in self.exposed_apis:
                if parent in self.crypto_lib.keys():
                    parent_exposed_apis = self.crypto_lib[parent]['APIs']
                else:
                    parent_exposed_apis = self.get_api_exposed(parent)
                self.exposed_apis[parent] = parent_exposed_apis
            
            if child not in self.used_apis:
                child_used_apis = self.get_api_calls(child)
                self.used_apis[child] = child_used_apis
            
            edge_attrs[edge] = {'APIs': set(self.exposed_apis[parent]) & set(self.used_apis[child])}

        return edge_attrs
    

if __name__ == "__main__":
    import sys
    import cProfile, io, pstats

    args = sys.argv[1:]

    if len(args) == 0:
        output_dir = 'out-coreutils'
    else:
        output_dir = args[0]

    os.makedirs(output_dir, exist_ok=True) 

    analysis = APIAnalysis(os.path.join(output_dir,"dependency.pickle"))


    pr = cProfile.Profile()
    pr.enable()

    analysis.gen_report(output_dir)

    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumtime')
    ps.print_stats()

    with open(os.path.join(output_dir, 'api.prof'), 'w+') as f:
        f.write(s.getvalue())
