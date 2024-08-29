
from BaseAnalysis import BaseAnalysis
from APIAnalysis import APIAnalysis
import networkx as nx
import pickle
import time
import angr
import os

class TraceAnalysis(BaseAnalysis):

    def __init__(self, apiAnalaysis, verbose=0):
        if isinstance(apiAnalaysis, str):
            apiAnalaysis = pickle.load(open(apiAnalaysis,'rb'))

        if not isinstance(apiAnalaysis, APIAnalysis):
            raise Exception('Sth is wrong')
        
        super().__init__(apiAnalaysis.scan_folder, apiAnalaysis.crypto_lib_desc, verbose)

        self.api_graph = apiAnalaysis.api_graph

        self.crypto_lib = apiAnalaysis.crypto_lib
        self.elf_files = apiAnalaysis.elf_files
        self.trace_graph = nx.DiGraph()


        # root nodes dont have used apis
        self.used_apis = apiAnalaysis.used_apis

        # leaf nodes dont have exposed apis
        self.exposed_apis = apiAnalaysis.exposed_apis

        self.function_traces = dict()

        # remove unrelated files
        self.elf_files = list(filter(lambda elf: elf in self.api_graph.nodes, self.elf_files))

        self.cfg = dict()
        self.projects = dict()

        self.elf_cfgtime = dict()
        self.lib_cfgtime = dict()
        self.elf_size = dict()
        self.lib_size = dict()

    
    def gen_report(self, output_folder=None):
        report, qv_apps = self.analyze()

        #print('App CFG time', self.elf_cfgtime)
        #print('Total App CFG time', sum(self.elf_cfgtime.values()))
        #print('App Bin Size', self.elf_size)
        #print('Total App Bin Size', sum(self.elf_size.values()))
        #print('Num Apps', len(self.elf_size.values()))

        #print('Lib CFG time', self.lib_cfgtime)
        #print('Total Lib CFG time', sum(self.lib_cfgtime.values()))
        #print('Lib Bin Size', self.lib_size)
        #print('Total Lib Bin Size', sum(self.lib_size.values()))
        #print('Num Libs', len(self.lib_size.values()))


        full_report = {}
        metadata = {"num_apps_before": len(self.elf_files), "num_total_before": len(self.api_graph.nodes), "num_apps_after": len(report)}
        full_report['metadata'] = metadata
        full_report['QV_apps'] = qv_apps
        full_report["report"] = report
        full_report["app_cfg_time"] = self.elf_cfgtime
        full_report["app_size"] = self.elf_size
        full_report["lib_cfg_time"] = self.lib_cfgtime
        full_report["lib_size"] = self.lib_size

        if output_folder is not None:
            self.write_report(full_report, "trace.txt", output_folder)
            pickle.dump(self, open(os.path.join(output_folder, "trace.pickle"), 'wb'))


        return full_report
    
    def analyze(self):

        report = list()
        qv_apps = list()

        for idx, elf in enumerate(self.elf_files):

            for libpath, _ in self.crypto_lib.items():

                fn_trace = self._get_trace(elf, 'main', libpath)

                if fn_trace is not None:
                    qv_apps.append(elf)
                    report.append({'elf': elf, 'trace': fn_trace, 'cryptolib': libpath})

        return report, qv_apps
    
    def _get_trace(self, elf, exposed_api, libpath):

        if elf in self.crypto_lib.keys():
            return None

        if elf not in self.projects:
            self.projects[elf] = angr.Project(elf, load_options={'auto_load_libs': False})
        if elf not in self.cfg:
            s = time.time()
            cfg = self.projects[elf].analyses.CFGFast()
            t = round(time.time()-s,2)
            print('CFG for', elf, 'takes', t)
            if elf in self.elf_files:
                self.elf_cfgtime[elf] = t
                self.elf_size[elf] = os.path.getsize(elf)
            else:
                self.lib_cfgtime[elf] = t
                self.lib_size[elf] = os.path.getsize(elf)
            self.cfg[elf] = cfg.copy()

        if exposed_api == 'main':
            exposed_api_addr = self._find_main(self.projects[elf])
            assert(exposed_api_addr is not None)
        else:
            exposed_api_addr = self.projects[elf].loader.find_symbol(exposed_api).rebased_addr

        parents = list(self.api_graph.predecessors(elf))
        assert(len(parents)>=1)
        
        for parent in parents:
            # TODO: sort by shortest path
            #print('cur node', elf, 'parent', parent)
            #print(self.api_graph[parent][elf]['APIs'])
            #print(hex(exposed_api_addr), exposed_api)

            for used_api in self.api_graph[parent][elf]['APIs']:
                #if exposed_api == 'main':
                #    print('For main, used apis are:', elf, parent, self.api_graph[parent][elf]['APIs'])
                    
                # for some reasons, angr may not find this api in plt section (perhaps due to compiler's optimization)
                # e.g., libssl's ASN1_OBJECT_free used by /usr/bin/openvpn3
                if used_api not in self.projects[elf].loader.main_object.plt:
                    print('Not found', used_api)
                    continue

                used_api_addr = self.projects[elf].loader.main_object.plt[used_api]

                has_path = nx.has_path(self.cfg[elf].kb.functions.callgraph, exposed_api_addr, used_api_addr)

                #print('Finding fn trace from:', elf, exposed_api, 'to', parent, used_api, has_path)

                if not has_path:
                    continue
                
                if parent == libpath:
                    trace = self._get_function_trace(elf, self.cfg[elf], exposed_api_addr, used_api_addr)
                    return trace + [(libpath, used_api)]

                ancestor_trace = self._get_trace(parent, used_api, libpath)
                if ancestor_trace is None:
                    continue

                trace = self._get_function_trace(elf, self.cfg[elf], exposed_api_addr, used_api_addr)
                return trace + ancestor_trace

        return None

    
    def _get_function_trace(self, elf, cfg, start_addr, end_addr):
        path = nx.shortest_path(cfg.kb.functions.callgraph, start_addr, end_addr)
        return [(elf,str(self._which_fn(cfg,p))) for p in path]

    def _find_main(self, project):

        main_symbol = project.loader.main_object.get_symbol('main')
        if main_symbol is not None:
            return main_symbol.rebased_addr
        
        # Get the entry state of the binary
        state = project.factory.entry_state()
        
        # Create a simulation manager to explore the binary
        simgr = project.factory.simgr(state)
        
        # Step through the program until a target function is called
        while simgr.active:
            for state in simgr.active:
                # Check if the state is calling __libc_start_main
                if state.addr == project.loader.find_symbol('__libc_start_main').rebased_addr:
                    # Get the address of the function call
                    main_address = state.solver.eval(state.regs.rdi)
                    return main_address
            
            # Step forward in the simulation
            simgr.step()
        
        return None
    
    def _which_fn(self, cfg, addr):
        dist = 0x1000000
        out = None
        for function in cfg.kb.functions.values():
            start_addr = function.addr
            end_addr = start_addr + function.size
            # we can trust start_addr
            if start_addr == addr:
                return function.name
            
            if start_addr <= addr < end_addr:

                # apparently, function.size is not accurate...
                if addr - start_addr < dist:
                    dist = addr - start_addr
                    out = function

        assert(False)
    

if __name__ == "__main__":
    import logging
    import sys
    import cProfile, io, pstats

    args = sys.argv[1:]

    if len(args) == 0:
        output_dir = 'out-coreutils'
    else:
        output_dir = args[0]

    os.makedirs(output_dir, exist_ok=True) 

    logging.getLogger('angr').setLevel(logging.CRITICAL)

    analysis = TraceAnalysis(os.path.join(output_dir,"api.pickle"))

    pr = cProfile.Profile()
    pr.enable()

    analysis.gen_report(output_dir)

    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumtime')
    ps.print_stats()

    with open(os.path.join(output_dir, 'trace.prof'), 'w+') as f:
        f.write(s.getvalue())
