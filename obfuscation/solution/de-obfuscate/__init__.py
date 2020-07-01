from binaryninja import *
import os

def bootstrap(bv, addr):
    
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(plugin_dir, 'de-obfuscate.py')
    print(src_path)
    src = open(src_path, 'rb').read()
    exec src in globals()
    
    # deobfuscate_function is defined in de-obfuscate.py
    deobfuscate_function(bv, addr)


def bootstrap2(bv, addr):
    
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(plugin_dir, 'de-obfuscate.py')
    print(src_path)
    src = open(src_path, 'rb').read()
    exec src in globals()
    
    # deobfuscate_function is defined in de-obfuscate.py
    simplify_func(bv, addr)

def bootstrap3(bv, addr):
    
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(plugin_dir, 'de-obfuscate.py')
    print(src_path)
    src = open(src_path, 'rb').read()
    exec src in globals()
    
    # deobfuscate_function is defined in de-obfuscate.py
    simplify_bbl_handler(bv, addr)

PluginCommand.register_for_address("Deobfuscate",
                                   "Remove tcc",
                                   bootstrap)

PluginCommand.register_for_address("Simplify",
                                   "Simplify tcc",
                                   bootstrap2)

PluginCommand.register_for_address("Simplify BBL",
                                   "Simplify tcc",
                                   bootstrap3)