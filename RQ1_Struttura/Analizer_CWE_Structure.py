import graphviz
import os
import pandas as pd
import csv
import xml.etree.ElementTree as ET
import pprint
import argparse
import pydotplus
import networkx
import pydot
import math


def is_perfect_tree(G, root=None):
    if root is None:
        root = [n for n, d in G.in_degree() if d == 0][0]

    levels = {}

    def traverse(node, level=0):
        if level not in levels:
            levels[level] = 0
        levels[level] += 1

        children = list(G.successors(node))
        for child in children:
            traverse(child, level + 1)

    traverse(root)

    max_level = max(levels.keys())
    for level in range(max_level):
        if levels[level] != 2 ** level:
            return False

    return True


def is_complete_tree(G, root=None):
    if root is None:
        root = [n for n, d in G.in_degree() if d == 0][0]

    n = len(G.nodes())
    max_level = math.floor(math.log2(n + 1))

    nodes_by_level = {i: [] for i in range(max_level + 1)}

    def assign_level(node, level=0):
        nodes_by_level[level].append(node)
        for child in G.successors(node):
            assign_level(child, level + 1)

    assign_level(root)

    for level, nodes in nodes_by_level.items():
        if level < max_level and len(nodes) != 2 ** level:
            return False
        if level == max_level and len(nodes) != n - 2 ** max_level + 1:
            return False

    return True

def is_balanced_tree(G, root=None):
    def depth(node, d=0):
        depths[node] = d
        d += 1
        for child in G.successors(node):
            depth(child, d)

    if root is None:
        root = [n for n, d in G.in_degree() if d == 0][0]

    depths = {}
    depth(root)

    leaf_depths = [depths[node] for node in G.nodes() if G.out_degree(node) == 0]

    max_depth = max(leaf_depths)
    min_depth = min(leaf_depths)

    # You can modify this condition based on how balanced you want the tree to be.
    return max_depth - min_depth <= 1

def get_elem(elem):
    return elem.split("_")[0]

def read_list(filename):

    try:
        stopword = open(filename, "r")
        lines = stopword.read().split('\n')
        for i,e in enumerate(lines):
            lines[i] = lines[i].strip()
            arr = lines[i].split("-")
            lines[i] = arr[0] + arr[1]
        lines = mapping_on_cwe532(lines)
        return lines
    except Exception as e:
        print(e)




def write_list(list, filename):
    textfile = open(filename, "w")
    for element in list:
        textfile.write(element + "\n")
    textfile.close()


def get_complete_cwe(path_xml):
    # Ricavo lista dei figli
    #path_excell = "C:\\Users\\Valentino\\Documents\\Universita\\Tesi\\2. Bugginess\\699.csv"
    #df = pd.read_csv(path_excell, usecols=['CWE-ID', 'Related Weaknesses'], index_col=None)  
    ##print(df.head())
   

    tree = ET.parse(path_xml)
    root = tree.getroot()
    tmp = {}
    l =[]
    for child in root[0]:
        l.append(str(child.attrib["ID"]))
        tmp["CWE"+str(child.attrib["ID"])] = {}
        tmp["CWE"+str(child.attrib["ID"])] = {}
        tmp["CWE"+str(child.attrib["ID"])]["status"] = child.attrib["Status"]

       
        for child_l1 in child:
            ##print(child_l1.tag)
            if child_l1.tag == "{http://cwe.mitre.org/cwe-6}Related_Weaknesses":

                tmp["CWE"+str(child.attrib["ID"])]["edges"] = []
                tmp["CWE"+str(child.attrib["ID"])]["property"] = []
                for elem in child_l1: 
                    tmp["CWE"+str(child.attrib["ID"])]["edges"].append("CWE"+str(elem.attrib["CWE_ID"]))
                    tmp["CWE"+str(child.attrib["ID"])]["property"].append(elem.attrib["Nature"])
    
    #print(len(list(set(l))))
    return tmp


def get_property(elem, dict):
    for idx, edge in enumerate(dict["edges"]):
        if elem == edge:
            if dict["property"][idx] == "ChildOf":
                return dict["property"][idx]
    return "-1"


def delete_double_father(dict):

    for key, elem in dict.items():
        temp_edge_list = []
        temp_property_list = []

        if "edges" in elem.keys():
            find_list = {}
            for edge in elem["edges"]:
                find_list[edge] = 0
            for idx, edge in enumerate(elem["edges"]):
                property = elem["property"][idx]
                for idx_2, edge_2 in enumerate(elem["edges"]):
               
                    if edge == edge_2 and idx != idx_2:
                        find_list[edge] += 1
                        tmp = get_property(edge, elem)
                        if not tmp == "-1":
                            property = tmp
                        break
                if find_list[edge] < 2:
                    temp_edge_list.append(edge)
                    temp_property_list.append(property)
        elem["edges"] = temp_edge_list
        elem["property"] = temp_property_list
    return dict


def in_list(key, list):
    for elem in list:
        if elem == key:
            return True
    return False


def reverse_father(d):

    reverse_dict = {}
    rel_dict = {'ChildOf': 'ParentOf',
                'PeerOf': 'PeerOf', 
                'CanPrecede': 'CanSuccede', 
                'CanAlsoBe': 'CanAlsoBe', 
                'Requires': 'Requires', 
                'StartsWith': 'EndsWith'}
    #Inizializzazione dizionario
    for key, elem in d.items():
        if "edges" in elem.keys() and len(elem["edges"])!=0:

            for father in elem["edges"]:

                reverse_dict[father] = {}
                reverse_dict[father]["childs"] = []
                reverse_dict[father]["relationship"] = []
        else:    
            reverse_dict[key] = {}
            reverse_dict[key]["childs"] = []
            reverse_dict[key]["relationship"] = []

    # inserisci quelle che sono le foglie
    for key, elem in d.items():
        found = False
        for key2, elem2 in d.items():
            if key2 != key:
                for e in elem2["edges"]:
                    if e == key:
                        found = True
                        break
        if not found :
            reverse_dict[key] = {}
            reverse_dict[key]["childs"] = []
            reverse_dict[key]["relationship"] = []


    for key, elem in d.items():
        if "edges" in elem.keys() and len(elem["edges"])!=0:
            for idx, father in enumerate(elem["edges"]):
                if not in_list(key, reverse_dict[father]["childs"]):
                    reverse_dict[father]["childs"].append(key)
                    reverse_dict[father]["relationship"].append(rel_dict[elem["property"][idx]])
    return reverse_dict


def get_list_property(dict_mitre):
    rel = {}
    for key, elem in dict_mitre.items():
        if "edges" in elem.keys():
            for e in elem["property"]:
                rel[e]="property"
    #print(rel)


def get_list_status(dict_mitre):
    rel = {}
    for key, elem in dict_mitre.items():
        rel[elem["status"]]="status"   
    #print(rel)


def search_root(d_mitre):
    count_no_edge = 0
    count_list_empty = 0
    l_root = []
    l_property = []
    for key in d_mitre.keys():
        if "edges" not in d_mitre[key].keys() or d_mitre[key]['edges']==[]:
            l_root.append(key)
            l_property.append(d_mitre[key])
            count_no_edge+=1

    #print("Conteggio nodi senza padre: "+str(count_no_edge))
    #print("Lista radici: ")
    #print(l_root)
    #print(l_property)
    return l_root


def create_graph(d_mitre, list_cwe):

    # Dizionario contenente nodi juliet e archi uscenti
    tmp_tree = {}
    fill_d = []

    for juliet_cwe in list_cwe:
        if juliet_cwe in d_mitre.keys():
            tmp_tree[juliet_cwe]={}

            if "edges" in d_mitre[juliet_cwe].keys(): 
                tmp_tree[juliet_cwe]["edges"] = d_mitre[juliet_cwe]["edges"]
                tmp_tree[juliet_cwe]["property"] = d_mitre[juliet_cwe]["property"]
                fill_d += d_mitre[juliet_cwe]["edges"]

    # fill_d è la lista degli archi uscenti dai nodi juliet
    while len(fill_d)>0:
        node = d_mitre[fill_d[0]]
        if fill_d[0] not in tmp_tree.keys():
            tmp_tree[fill_d[0]]={}

            if "edges" in node.keys():
                fill_d += node["edges"]
                tmp_tree[fill_d[0]]["edges"] = node["edges"]
                tmp_tree[fill_d[0]]["property"] = node["property"]
        fill_d.pop(0)
    return tmp_tree

    
def get_counts(d):
    count_childof=0
    count_CanAlsoBe=0
    count_CanPrecede=0
    count_StartsWith=0
    count_PeerOf=0
    count_not_nature=0
    count_requires = 0
    
    for key, elem in d.items():

        if "edges" in elem.keys():
            
            for e in elem["property"]:
               
                if e == "ChildOf":
                    count_childof = count_childof+1
                elif e == "CanAlsoBe":
                    count_CanAlsoBe = count_CanAlsoBe+1
                elif e == "CanPrecede":
                    count_CanPrecede = count_CanPrecede+1
                elif e == "StartsWith":
                    count_StartsWith = count_StartsWith+1
                elif e == "PeerOf":
                    count_PeerOf = count_PeerOf+1
                elif e == "Requires":
                    count_requires = count_requires+1
        else:
            count_not_nature+=1
    
    #print("Numero elementi childof: "+str(count_childof))
    #print("Numero elementi CanAlsoBe: "+str(count_CanAlsoBe))
    #print("Numero elementi CanPrecede: "+str(count_CanPrecede))
    #print("Numero elementi StartsWith: "+str(count_StartsWith))
    #print("Numero elementi PeerOf: "+str(count_PeerOf))
    #print("Numero elementi senza archi, Radici: "+str(count_not_nature))
    #print("Numero elementi Requires: "+str(count_requires))


def get_num_juliet_in_mitre(juliet, mitre):
    count = 0
    l = []
    for cwe in juliet:
        found = False
        for key in mitre.keys():
            if cwe == key:
                count+=1
                found = True
                break
        if not found:
            l.append(cwe)

    #print("Numero cwe del dataset in mitre: "+str(count)+" sul totale di: "+str(len(juliet)))
    #print("La lista dei mancanti: ")
    #print(l)



def render_graph(root_path, root_node, tmp_tree, list_cwe_juliet , list_cwe_dataset_tool, list_cwe_intersect, t,reverse=False):
    dot = graphviz.Digraph(name='Family Tree', graph_attr={'rankdir':'LR','splines': 'spline', 'splines': 'true','ranksep': '4', "nodesep":"1"})

    intersect = False
    oss = False
    jts = False
    for key, elem in tmp_tree.items():
        for cwe in list_cwe_intersect:
            if key == cwe:
                intersect = True
        for cwe in list_cwe_juliet:
            if key == cwe and cwe not in list_cwe_intersect:
                jts = True
        for cwe in list_cwe_dataset_tool:
            if key == cwe and cwe not in list_cwe_intersect:
                oss = True
    c = graphviz.Digraph(name='clusterA', node_attr={'shape': 'plaintext'})
    c.attr(label='Legenda')
    c.attr(fontsize='20')

    if t=="R" and not intersect and oss and jts:
        c.node("Research", "Research", color="black",style="filled",fillcolor="white",shape="underline")
        c.node("JTS", "JTS", color="black",style="filled",fillcolor="yellow",shape="plain")
        c.node("OSS", "OSS", color="black",style="filled",fillcolor="#f08989",shape="plain")
    elif t=="R" and not intersect and not oss and jts:
        c.node("Research", "Research", color="black",style="filled",fillcolor="white",shape="underline")
        c.node("JTS", "JTS", color="black",style="filled",fillcolor="yellow",shape="plain")
    elif t=="R" and not intersect and oss and not jts:
        c.node("Research", "Research", color="black",style="filled",fillcolor="white",shape="underline")
        c.node("OSS", "OSS", color="black",style="filled",fillcolor="#f08989",shape="plain")
    elif t=="R" and intersect and oss and not jts:
        c.node("Research", "Research", color="black",style="filled",fillcolor="white",shape="underline")
        c.node("OSS", "OSS", color="black",style="filled",fillcolor="#f08989",shape="plain")
        c.node("JTS&OSS", "JTS&OSS", color="black",style="filled",fillcolor="orange",shape="plain")
    elif t=="R" and intersect and not oss and jts:
        c.node("Research", "Research", color="black",style="filled",fillcolor="white",shape="underline")
        c.node("JTS", "JTS", color="black",style="filled",fillcolor="yellow",shape="plain")
        c.node("JTS&OSS", "JTS&OSS", color="black",style="filled",fillcolor="orange",shape="plain")
    elif t=="R" and intersect and oss and jts:
        c.node("Research", "Research", color="black",style="filled",fillcolor="white",shape="underline")
        c.node("JTS", "JTS", color="black",style="filled",fillcolor="yellow",shape="plain")
        c.node("OSS", "OSS", color="black",style="filled",fillcolor="#f08989",shape="plain")
        c.node("JTS&OSS", "JTS&OSS", color="black",style="filled",fillcolor="orange",shape="plain")
    if t=="I":
        c.node("Research", "Research", color="black",style="filled",fillcolor="white",shape="underline")
        c.node("JTS&OSS", "JTS&OSS", color="black",style="filled",fillcolor="yellow",shape="plain")
    if t=="J":
        c.node("Research", "Research", color="black", style="filled", fillcolor="white", shape="underline")
        c.node("JTS", "JTS", color="black", style="filled", fillcolor="yellow", shape="plain")
    if t=="S":
        c.node("Research", "Research", color="black",style="filled",fillcolor="white",shape="underline")
        c.node("OSS", "OSS", color="black",style="filled",fillcolor="yellow",shape="plain")


    dot.subgraph(c)
    i=0
    for key, elem in tmp_tree.items():
        s = 'underline'
        c = 'black'
        st = 'filled'
        fill = 'white'

        for cwe in list_cwe_juliet:
            if key == cwe:
                s = 'plain'
                c = 'black'
                st = 'filled'
                fill = 'yellow'
        for cwe in list_cwe_dataset_tool:
            if key == cwe:
                s = 'plain'
                c = 'black'
                st = 'filled'
                fill = '#f08989'

        for cwe in list_cwe_intersect:
            if key == cwe:
                s = 'plain'
                c = 'black'
                st = 'filled'
                fill = 'orange'
        dot.node(key, key, color=c,style=st,fillcolor=fill,shape=s)
        i+=1
    
    if reverse:
        for key, elem in tmp_tree.items():
            if "childs" in elem.keys():
                for i, edge in enumerate(elem["childs"]):
                    dot.edge(key, edge)
    else:
        for key, elem in tmp_tree.items():
            if "edges" in elem.keys():
                for i, edge in enumerate(elem["edges"]):
                    dot.edge(edge, key)
                ##print(edge, key)
    ##print(tmp_tree)

    dot.render(root_path+"/output_alberi/"+root_node+'.dot', view=False)
    (graph,) = pydot.graph_from_dot_file(root_path+"/output_alberi/"+root_node+'.dot')
    graph.write_png(root_path+"/output_png/"+root_node+'.png')
    line_result = calculate_metrics(root_node, dot, root_path + "\output_",root_node+".txt")
    #dot = render_graph(tmp_tree, list(vertex_min_cover), "Min_Vertex_Tree_Albero_Completo", root_folder, True)
    return line_result


def divide_graph(table_result, root_path, d, list_cwe_juliet, list_cwe_tool, list_cwe_intersect, t):
    roots = search_root(d)
    #print("\n\nROOTS: ")
    #print(roots)

    reverse_dict = reverse_father(d)
    
    for i,root in enumerate(roots):
        tmp_tree = {}
        fill_d = []
        #INIZIALIZZAZIONE 
        tmp_tree[root]={}
        if "childs" in reverse_dict[root].keys(): 
            tmp_tree[root]["childs"] = reverse_dict[root]["childs"]
            tmp_tree[root]["relationship"] = reverse_dict[root]["relationship"]
            fill_d += reverse_dict[root]["childs"]


        while len(fill_d)>0:
            node = reverse_dict[fill_d[0]]
            if fill_d[0] not in tmp_tree.keys():
                tmp_tree[fill_d[0]]={}

                if "childs" in node.keys():
                    fill_d += node["childs"]
                    tmp_tree[fill_d[0]]["childs"] = node["childs"]
                    tmp_tree[fill_d[0]]["relationship"] = node["relationship"]
            fill_d.pop(0)
        table_result = table_result + render_graph(root_path, root, tmp_tree, list_cwe_juliet, list_cwe_tool, list_cwe_intersect, t,True)
    write_metric(root_path + "\\result_table.txt", table_result)
    return table_result

def mapping_on_cwe532(l):
    for cwe in l:
        if cwe == "CWE533":
            cwe = "CWE532"
    if "CWE534" in l:
        l.pop(l.index("CWE534"))
    return l


def write_metric(filename, text):
    textfile = open(filename, "w")
    textfile.write(text)
    textfile.close()


def calculate_metrics(root_node, dot, root, filename):
    dotplus = pydotplus.graph_from_dot_data(dot.source)
    nx_graph = networkx.nx_pydot.from_pydot(dotplus)

    is_tree = False
    diameter = None
    height = None
    if networkx.is_tree(nx_graph):
        print("Il grafo è un albero.")
        is_tree = True
    else:
        print("Il grafo non è un albero.")

    if is_tree:
        height = max(networkx.single_source_shortest_path_length(nx_graph, root_node).values())
        print(height)
        print(root_node)
    else:
        diameter = networkx.eccentricity(nx_graph, root_node)
        print(diameter)


    # Grado massimo del grafo ossia il numero max di figli
    degree_values = nx_graph.out_degree()
    max_degree_node = max(nx_graph.nodes, key=nx_graph.degree)
    max_degree = nx_graph.degree(max_degree_node)
    #print("GRADO" + str(degree_values))
    """max_degree = (0, 0)
    for element in degree_values:
        if element[1] > max_degree[1]:
            max_degree = element
    """
    # Livello a cui ogni nodo appartiene nel grafo
    levels = networkx.single_source_shortest_path_length(nx_graph, root_node)
    #print("\n\n\nLIVELLI")
    #print(networkx.single_source_shortest_path_length(nx_graph, root_node))
    #print(root_node)
    ##print(nx_graph.nodes)

    # Altezza del grafo, massimo livello raggiunto
    max_height = 0
    for k,v in levels.items():
        if v>max_height:
            max_height = v
    max_height = max_height + 1
    #print("Max height del grafo: "+str(max_height))


    # Bilanciamento
    """#print(filename)
    if "CWE707" in filename:
        leaf = [x for x in nx_graph.nodes() if nx_graph.out_degree(x)==0 and nx_graph.in_degree(x)==1]
        #print(leaf)
        balanced = "True"
        for k,v in levels.items():
            if k in leaf:
                if v != (max_height-1) and v != (max_height-2):
                    balanced = "False"
                    break

        exit(1)"""
    """leaf = [x for x in nx_graph.nodes() if nx_graph.out_degree(x) == 0 and nx_graph.in_degree(x) == 1]
    balanced = "True"
    for k, v in levels.items():
        if k in leaf:
            if v != (max_height - 1) and v != (max_height - 2):
                balanced = "False"
                break
    # Completezza, nodi intermedi grado N e tutte le foglie stessa profondita
    completeness = "True"
    if balanced == "False":
        completeness = "False"
    else:
        for k,v in levels.items():
            # Escludo l'ultimo livello

            if v < (max_height-1) :
                for element in degree_values:
                    if element[0] == k and element[1] != max_degree[1]:
                        completeness = "False"
                        break

    # Perfectness
    perfectness = "True"
    if completeness == "False":
        perfectness = "False"
    else:
        for k,v in levels.items():
            # Controllo solo l'ultimo livello se è pieno
            if v == (max_height-2) :
                for element in degree_values:
                    if element[0] == k and element[1] != max_degree[1]:
                        perfectness = "False"
                        break
    """
    betweenness_centrality = networkx.betweenness_centrality(nx_graph)
    vertex_min_cover = networkx.algorithms.approximation.vertex_cover.min_weighted_vertex_cover(nx_graph, weight=None)
    betweenness_centrality = {k: v for k, v in sorted(betweenness_centrality.items(), key=lambda item: item[1], reverse=True)}
    write_metric(root + "betwenness" + "\Betweeness_centrality" + filename, str(betweenness_centrality))
    write_metric(root + "degree" + "\Degree" + filename, str(max_degree_node)+" degree="+str(max_degree))
    write_metric(root + "level" + "\Level" + filename, str(levels))
    write_metric(root + "max_height" + "\Height" + filename, "Max Height="+str(max_height))
    #write_metric(root + "balanced" + "\Balanced" + filename, "Balanced="+balanced)
    #write_metric(root + "completeness" + "\Completeness" + filename, "Completeness="+completeness)
    #write_metric(root + "perfectness" + "\Perfectness" + filename, "Perfectness="+perfectness)
    write_metric(root + "min_ver_cover" + "\min_vertex_cover" + filename, str(vertex_min_cover))

    # Root + grado_max + is_tree + diametro + altezza + altezza a mano da confrontare
    if is_tree:
        is_tree="Si"
        h = height
    else:
        is_tree="No"
        h = diameter

    line_result = root_node + " & " + str(max_degree_node)+":"+str(max_degree) + " & " + is_tree + " & " + str(h) + " \\ " + " \n"
    return line_result


def write_cwe_mitre(l):
    print(len(l))
    with open("cwe_mitre.txt", 'w') as file:
        for row in l:
            file.write("CWE-"+row.split("CWE")[1]+"\n")

def get_num_nodes(d):
    l = []
    for key, elem in d.items():
        l.append(key)
    print("Numero nodi: "+str(len(l)))
    print("Numero nodi univoci: "+str(len(set(l))))
    write_cwe_mitre(list(set(l)))


def main():
    """
        In giallo i CWE di Juliet
            In rosso i 29 CWE Rilevati nel dataset
            Arancione se un CWE è preso Juliet e da NOI
    """
    # Ricavo lista di cwe da juliet java
    list_cwe_juliet = read_list("cwe_juliet.txt")
    list_cwe_tool = read_list("cwe_OSS.txt")
    list_cwe_intersect = read_list("cwe_JTS_OSS.txt")

    ###############################################

    """
        Con ChildOf sto dicendo che la chiave (key) è figlia della foglia (nella lista edges)
        Quindi l'idea è che se la lista di edges è vuota significa che la key non è figlia di nessuno e quindi radice.
    """
    current_directory = os.getcwd()
    path_complete_tree = os.path.join(current_directory, r"research_1000.xml")


    dict_mitre = get_complete_cwe(path_complete_tree)
    #print(dict_mitre)


    get_list_property(dict_mitre)
    get_list_status(dict_mitre)
    search_root(dict_mitre)
    get_counts(dict_mitre)
    get_num_nodes(dict_mitre)

    #get_num_juliet_in_mitre(list_cwe_dataset, dict_mitre)

    ###################################################
    #Preprocessing - elimina archi non childof e padri doppi
    for key, elem in dict_mitre.items():
        if "edges" in elem.keys():
            tmp_list = elem["property"].copy()
            tmp_list1 = elem["edges"].copy()
            for p in  elem["property"]:
                if p != "ChildOf":
                    for i, tmp_elem in enumerate(tmp_list):
                        if tmp_elem == p:
                            tmp_list.pop(i)
                            tmp_list1.pop(i)
            elem["property"] = tmp_list    
            elem["edges"] = tmp_list1 


    dict_mitre = delete_double_father(dict_mitre)

    get_list_property(dict_mitre)
    #-----------------------------------------------------#
    #print("len")
    #print(len(dict_mitre))
    #print("_--------------------------------_")
    # Grafo Rsearch con nodi JTS
    print("Grafo Research con nodi JTS")
    graph_intersect_rj = create_graph(dict_mitre, list_cwe_juliet)
    table_result_rj = ""
    table_result_rj=divide_graph(table_result_rj, "Output_Research_JTS", graph_intersect_rj, list_cwe_juliet, [], [], "J")

    #print("len")
    #print(len(dict_mitre))
    #print("_--------------------------------_")
    # Grafo Rsearch con nodi Vulas
    print("Grafo Research con nodi Vulas")
    graph_intersect_rs = create_graph(dict_mitre, list_cwe_tool)
    table_result_rs = ""
    table_result_rs=divide_graph(table_result_rs, "Output_Research_Vulas", graph_intersect_rs, list_cwe_tool, [], [], "S")
    #print("len")
    #print(len(dict_mitre))
    #print("_--------------------------------_")
    # Grafo Rsearch con nodi Vulas e JTS
    print("Grafo Research con nodi JTS e Vulas")
    graph_intersect_rjs = create_graph(dict_mitre, list_cwe_intersect)
    table_result_rjs = ""
    table_result_rjs=divide_graph(table_result_rjs, "Output_Research_Vulas_JTS", graph_intersect_rjs, list_cwe_intersect, [], [], "I")
    #print("len")
    #print(len(dict_mitre))
    #print("_--------------------------------_")
    # Grafo Research colorato
    print("Grafo Research")
    table_result = ""
    table_result=divide_graph(table_result, "Output_Research",dict_mitre, list_cwe_juliet, list_cwe_tool, list_cwe_intersect, "R")



    #-------------------------------Alberi unificati-------------------------------------#




    # Grafo Rsearch con nodi JTS
    # Creazione root unica
    roots = search_root(graph_intersect_rj)
    d = {}
    d["edges"] = ["Root"]
    d["property"] = ["ChildOf"]
    graph_intersect_rj["Root"] = {"edges": [], "property": []}
    for r in roots:
        graph_intersect_rj[r] = d
    divide_graph(table_result_rj,"Output_Research_JTS", graph_intersect_rj, list_cwe_juliet, [], [], "J")

    # Grafo Rsearch con nodi Vulas
    # Creazione root unica
    roots = search_root(graph_intersect_rs)
    d = {}
    d["edges"] = ["Root"]
    d["property"] = ["ChildOf"]
    graph_intersect_rs["Root"] = {"edges": [], "property": []}
    for r in roots:
        graph_intersect_rs[r] = d
    divide_graph(table_result_rs, "Output_Research_Vulas", graph_intersect_rs, list_cwe_tool, [], [], "S")

    # Grafo Rsearch con nodi Vulas e JTS
    roots = search_root(graph_intersect_rjs)
    d = {}
    d["edges"] = ["Root"]
    d["property"] = ["ChildOf"]
    graph_intersect_rjs["Root"] = {"edges": [], "property": []}
    for r in roots:
        graph_intersect_rjs[r] = d
    divide_graph(table_result_rjs, "Output_Research_Vulas_JTS", graph_intersect_rjs, list_cwe_intersect, [], [], "I")

    # Grafo Research colorato
    # Grafo Rsearch con nodi Vulas e JTS
    roots = search_root(dict_mitre)
    d = {}
    d["edges"] = ["Root"]
    d["property"] = ["ChildOf"]
    dict_mitre["Root"] = {"edges": [], "property": []}
    for r in roots:
        dict_mitre[r] = d
    divide_graph(table_result, "Output_Research", dict_mitre, list_cwe_juliet, list_cwe_tool, list_cwe_intersect, "R")



if __name__ == "__main__":
    main()