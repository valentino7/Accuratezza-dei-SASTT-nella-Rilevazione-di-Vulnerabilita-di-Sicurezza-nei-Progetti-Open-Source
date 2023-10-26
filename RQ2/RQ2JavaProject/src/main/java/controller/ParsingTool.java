package controller;


import entity.Rule;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import utils.Constants;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static IO.ReaderInputs.getAbsolute;
import static common.StringCommon.removeBom;

public class ParsingTool {

    public static String jLintPath = getAbsolute(Constants.REPORT_RESULTS) + "\\jlint";
    public static String pmdPath = getAbsolute(Constants.REPORT_RESULTS) + "\\pmd";
    public static String sptB = getAbsolute(Constants.REPORT_RESULTS) + "\\spotbugs";
    public static String fsb = getAbsolute(Constants.REPORT_RESULTS) + "\\findsec";
    public static String snyk = getAbsolute(Constants.REPORT_RESULTS) + "\\snyk";
    public static String vcg = getAbsolute(Constants.REPORT_RESULTS) + "\\vcg\\result.xml";

    static Map<String, List<Rule>> mapSPT = new HashMap<>(); //cwe:Rule
    static Map<String, List<Rule>> mapJlint = new HashMap<>(); //cwe:Rule
    static Map<String, List<Rule>> mapPMD = new HashMap<>(); //cwe:Rule
    static Map<String, List<Rule>> mapSnyk = new HashMap<>(); //cwe:Rule
    static Map<String, List<Rule>> mapFDS = new HashMap<>(); //cwe:Rule
    static Map<String, List<Rule>> mapVCG = new HashMap<>(); //cwe:Rule

    static ArrayList<Rule> listFindsec = new ArrayList<>(); //Rule <rule:file.java>
    static ArrayList<Rule> listJlint = new ArrayList<>(); //Rule <rule:file.java>
    static ArrayList<Rule> listSnyk = new ArrayList<>(); //Rule <rule:file.java>

    static ArrayList<Rule> listSptB = new ArrayList<>(); //Rule <rule:file.java>
    static ArrayList<Rule> listVCG = new ArrayList<>(); //Rule <rule:file.java>
    public static String bug;

    /**
     * @CartelleInput:
     *  Constants.REPORT_RESULTS: Directory contenente i reports generati dai tool
     *  Constants.REPORT_RESULTS + snyk: Directory contenente i reports generati da SNYK
     *  Constants.REPORT_RESULTS + vcg//result.xml: vcg genera un solo file di report
     *  Constants.REPORT_RESULTS + pmd: Directory contenente i reports generati da PMD
     *  Constants.MAPPING_CWE_PMD
     *  Constants.MAPPING_CWE_SNYK
     *
     *  @CartelleOutput:
     *      Constants.PATH_REPORTS_TOOLS: Directory contenente i reports generati dai tool
     *      REPORT_RESULTS + snyk: Directory contenente i reports generati da SNYK
     *      REPORT_RESULTS + vcg//result.xml: vcg genera un solo file di report
     *      REPORT_RESULTS + pmd: Directory contenente i reports generati da PMD
     */
    public static void main(String[] args) throws IOException, ParserConfigurationException, SAXException, ParseException {

        //Non più usati nella tesi
        /*parsingSpotBugs();
        parsingFindSecBugs();
        parsingJlint();*/

        parsingVCG();
        parsingSnyk();
        parsingPMD();
    }


    //////////////////////////////////////VCG///////////////////////////////////////

    private static void parsingVCG() throws ParserConfigurationException, IOException, SAXException {
        analyzeFileVCG();
        SaveCweVCG(getAbsolute(Constants.PATH_VCG_PARSING_REPORT), listVCG);
    }

    public static void SaveCweVCG(String fileName, ArrayList<Rule> listVCG) throws FileNotFoundException {

        PrintWriter writer = new PrintWriter(fileName);
        for(Rule r : listVCG) {
            String file = r.getFile();
            String line = r.getBug();
            String cwe = r.getRule();
            StringBuilder sb = new StringBuilder();
            sb.append(file);
            sb.append(";");
            sb.append(cwe);
            sb.append(";");
            sb.append(line);
            sb.append('\n');
            writer.write(sb.toString());
            writer.flush();
        }
    }

    private static void analyzeFileVCG() throws ParserConfigurationException, IOException, SAXException {

        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new FileInputStream(vcg));
        Document doc = docBuilder.parse(is);


        NodeList nl = doc.getDocumentElement().getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            Node n = nl.item(i);
            if (n.getNodeName().equals("CodeIssue")) {
                parseVisualCodeGrepperIssue(n);
            }
        }

    }

    private static void parseVisualCodeGrepperIssue(Node n) {
        /*
         * // Here an example of how the CodeIssues looks <CodeIssue>
         *  <CodeIssue>
         *    <Priority>1</Priority>
         *    <Severity>Critical</Severity>
         *    <Title>Potential SQL Injection</Title>
         *    <Description>The application appears to allow SQL injection via a pre-prepared dynamic SQL statement. No validator plug-ins were located in the application's XML files.</Description>
         *    <FileName>C:\workspace\benchmark\src\main\java\org\owasp\benchmark\testcode\BenchmarkTest01304.java</FileName>
         *    <Line>52</Line>
         *    <CodeLine>			java.sql.PreparedStatement statement = connection.prepareStatement( sql,</CodeLine>
         *    <Checked>False</Checked>
         *    <CheckColour>LawnGreen</CheckColour>
         *  </CodeIssue>
         */

        //TestCaseResult tcr = new TestCaseResult();

        /*
               Esempio di filename: C:\Users\Valentino\CWE-1021\good_dbf259508c2b8e176d8cb837177aaadbf44f0670_JettyServer.java
               adesso c è il dollaro piu un atro campo:
               C:\Users\Valentino\CWE-1021\good $ dbf259508c2b8e176d8cb837177aaadbf44f0670 $ progressivo $JettyServer.java

               Esempio di nome in output: cweid_bad/good_fixcommit_filename; cwe predetto o cve name;#riga
         */
        String classname = getNamedChild("FileName", n).getTextContent();

        classname = classname.split("\\\\")[classname.split("\\\\").length - 2]+ "$"+classname.split("\\\\")[classname.split("\\\\").length - 1];

        Node catnode = getNamedNode("Title", n.getChildNodes());

        Rule r = new Rule(null, classname, null);
        if (figureCWE(catnode).equals("00"))
            r.setRule(catnode.getTextContent());
        else
            r.setRule(figureCWE(catnode));
        r.setBug(getNamedNode("Line", n.getChildNodes()).getTextContent());

        System.out.println("bug="+getNamedNode("Line", n.getChildNodes()).getTextContent());
        listVCG.add(r);
    }

    private static String figureCWE( Node catnode) {
        String cat = null;
        if (catnode != null) {
            cat = catnode.getTextContent();
        }
        if (cat.startsWith("Cipher.getInstance(")) {
            // Weak encryption
            return "327";
        } else if (cat.startsWith("Class Contains Public Variable: ")) {
            // Potential SQL Injection
            //return 89;
        }

        switch ( cat ) {
            //Cookies
            case "Poor Input Validation" : 		return "614";
            case "Use of AccessController.doPrivileged() in Public Method of Public Class" : return "264_668";
            case "ObjectInputStream" : return "20_77_502";

            case "Synchronized Code May Result in DeadLock" : return "399";
            case "SequenceInputStream" : return "20";
            case "Operation on Primitive Data Type" : return "190";
            //Injections
            case "Potential SQL Injection" :          return "89";
            //case "Operation on Primitive Data Type" : return 89;

            //Command injection
            case "java.lang.Runtime.exec Gets Path from Variable" : return "78";

            // XPath Injection
            case "FileInputStream" : 		                          return "643";
            case "java.io.FileWriter" : 		                      return "643";
            case "java.io.FileReader" : 		                      return "643";
            case "FileStream Opened Without Exception Handling" : return "643";

            //Weak random
            case "java.util.Random" : 		return "330";

            //Path traversal
            case "java.io.File" : 		                            return "22";
            case "java.io.FileOutputStream" : 		                return "22";
            case "getResourceAsStream" : 		                      return "22";
            //XSS
            case "Potential XSS" :		    return "79";

            // Trust Boundary Violation
            case "getParameterValues" : 	return "501";
            case "getParameterNames" : 		return "501";
            case "getParameter" : 		    return "501";

            default : return "00"; //System.out.println( "Unknown vuln category for VisualCodeGrepper: " + cat );
        }
    }

    public static Node getNamedChild(String name, Node parent) {
        NodeList children = parent.getChildNodes();
        return getNamedNode( name, children );
    }
    public static Node getNamedNode(String name, NodeList list) {
        for (int i = 0; i < list.getLength(); i++) {
            Node n = list.item(i);
            if (n.getNodeName().equals(name)) {
                return n;
            }
        }
        return null;
    }


    //////////////////////////////////////SNYK//////////////////////////////////////
    private static void parsingSnyk() throws ParserConfigurationException, IOException, SAXException, ParseException {

        //JSON parser object to parse read file

        System.out.println(snyk);
        String[] files = new File(snyk).list();

        int count = 0;
        for (String file : files) {
            Path path = Paths.get(snyk+"/"+file);
            System.err.println(file);

            removeBom(path);
            analyzeFileSnyk(file, snyk + "/" + file, listSnyk);


        }
        SaveCwe(getAbsolute(Constants.PATH_SNYK_PARSING_REPORT), mapSnyk);
    }

    private static boolean checkErrorFile(String path) throws IOException {
        // File path is passed as parameter
        File f = new File(path);
        BufferedReader br
                = new BufferedReader(new FileReader(f));

        String st;
        while ((st = br.readLine()) != null) {
            if (st.contains("FailedToRunTestError") || st.contains("FeatureNotSupportedForOrgError") || st.contains("Error")) {
                System.err.println("ERRORE SNYK");

                return true;
            }
        }
        return false;
    }


    private static void analyzeFileSnyk(String name, String file, ArrayList<Rule> l) throws IOException, ParseException {

        JSONParser jsonParser = new JSONParser();
        FileReader reader = new FileReader(file);
        //Read JSON file

        Object obj = jsonParser.parse(reader);
        JSONObject bugList = (JSONObject) obj;

        Object completeRun = bugList.get("runs");

        JSONArray completeRunArray = (JSONArray) completeRun;
        completeRunArray.forEach( emp -> parseTestData( (JSONObject) emp, l, name) );
    }

    private static void parseTestData(JSONObject emp, ArrayList<Rule> l, String name) {
        Object result = emp.get("results");
        Object rules = ((JSONObject) ((JSONObject) emp.get("tool")).get("driver")).get("rules");
        JSONArray rulesArray = (JSONArray) rules;
        JSONArray completeRunArray = (JSONArray) result;
        //rulesArray.forEach( rule -> takeMapping( (JSONObject) rule ) ); only for check mapping
        completeRunArray.forEach( emp2 -> parseResult( (JSONObject) emp2, l, name) );
    }


    private static void parseResult(JSONObject emp2, ArrayList<Rule> l, String name) {
        Object ruleId = emp2.get("ruleId");
        Object location = emp2.get("locations");
        JSONArray loc = (JSONArray) location;
        loc.forEach(emp3 -> {
            try {
                extractInfo( (JSONObject) emp3, ruleId, l, name);
            } catch (ParserConfigurationException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (SAXException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private static void extractInfo(JSONObject emp3, Object ruleId, ArrayList<Rule> l, String name) throws ParserConfigurationException, IOException, SAXException {
        JSONObject region = (JSONObject) ((JSONObject) emp3.get("physicalLocation")).get("region");
        JSONObject artifactLocation = (JSONObject)((JSONObject) emp3.get("physicalLocation")).get("artifactLocation");
        Object flowLine = region.get("startLine");
        Object uri = artifactLocation.get("uri");

        if(!uri.toString().contains(".java"))
            return;

        //String filename = name.split(".json")[0].substring(name.split(".json")[0].length()-40, name.split(".json")[0].length())
        //       +"$"+uri.toString().split("/")[uri.toString().split("/").length-1].split(".java")[0];

        String filename = name.split(".json")[0].substring(name.split(".json")[0].length()-40, name.split(".json")[0].length())
                +"$"+uri.toString().replace(".java","").trim();

        Rule r = new Rule("", filename , String.valueOf(flowLine));
        System.out.println("filename="+filename);
        System.out.println("name="+name);
        System.out.println("uri="+uri);
        System.out.println("\n\n\n");
        if (filename.contains("web_server"))
            System.exit(1);
        l.add(r);
        SearchMappingSnyk(filename, ruleId, flowLine, uri);
    }


    private static void SearchMappingSnyk(String name, Object ruleId, Object flowLine, Object uri) throws ParserConfigurationException, IOException, SAXException {
        File fXmlFile = new File(getAbsolute(Constants.MAPPING_CWE_SNYK));
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(fXmlFile);

        NodeList nList = doc.getElementsByTagName("scannerCode");

        int found = 0;
        for (int temp = 0; temp < nList.getLength(); temp++) {
            Node nNode = nList.item(temp);
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;
                String ruleCode = eElement.getAttribute("name");
                if(("java/"+ruleCode).equals(ruleId)){
                    String cweID = eElement.getElementsByTagName("cwe").item(0).getTextContent();
                    if (!mapSnyk.containsKey(cweID)){
                        List<Rule> list = new ArrayList<>();
                        mapSnyk.put(cweID, list);
                    }
                    System.out.println(uri.toString().split("/")[uri.toString().split("/").length-1].split("\\.")[0]);

                    Rule r = new Rule(cweID, name, String.valueOf(flowLine));
                    mapSnyk.get(cweID).add(r);
                    found = 1;
                }
            }
        }
        if (found == 0){
            System.out.println(ruleId.toString());

            if (!mapSnyk.containsKey(ruleId.toString())){
                List<Rule> list = new ArrayList<>();
                mapSnyk.put(ruleId.toString(), list);
            }
            Rule r = new Rule(ruleId.toString(), name, String.valueOf(flowLine));
            mapSnyk.get(ruleId.toString()).add(r);
        }
    }






    //////////////////////////////////////PMD//////////////////////////////////////
    private static void parsingPMD() throws ParserConfigurationException, IOException, SAXException {

        String[] files = new File(pmdPath).list();

        int s = files.length;
        int idx=0;
        for (String file : files) {
            System.err.println(idx+"-indice di-"+s);
            idx+=1;
            System.err.println("FILE: "+file);
            analyzeFilePMD(pmdPath+"/"+file);
        }
        SaveCwe(getAbsolute(Constants.PATH_PMD_PARSING_REPORT), mapPMD);
    }

    private static void analyzeFilePMD(String file) throws ParserConfigurationException, IOException, SAXException {

        File fXmlFile = new File(file);
        //list of rules founded for each java file
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(fXmlFile);

        ArrayList<Rule> listPmd = new ArrayList<>(); //Rule <rule:file.java>

        NodeList nList = doc.getElementsByTagName("violation");


        for (int temp = 0; temp < nList.getLength(); temp++) {

            Node nNode = nList.item(temp);
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;
                String line = eElement.getAttribute("beginline");
                String ruleCode = eElement.getAttribute("rule");
                if (!eElement.getAttribute("method").equals("")) {

                    Rule r = new Rule(ruleCode, file.split("/")[file.split("/").length - 1], eElement.getAttribute("method"));
                    listPmd.add(r);
                }
            }
        }
        SearchMappingPMD(listPmd, file);
    }

    private static void SearchMappingPMD(ArrayList<Rule> rules, String fileJava) throws ParserConfigurationException, IOException, SAXException {

        String line = " ";
        for(int i = 0; i<rules.size(); i++) {
            File file = new File(getAbsolute(Constants.MAPPING_CWE_PMD));
            FileReader fr = new FileReader(file);
            BufferedReader br = new BufferedReader(fr);
            String r = rules.get(i).getRule();

            String l = rules.get(i).getBug();
            int mappingCweRuleExists = 0;
            String fileJ = fileJava.split("/")[fileJava.split("/").length-1];


            while ((line = br.readLine()) != null) {

                if (line.contains(r)){

                    System.err.println(line);
                    String[] parts = line.split(";");
                    String cwe = parts[0].split(":")[1];

                    if (!mapPMD.containsKey(cwe)){
                        List<Rule> list = new ArrayList<>();
                        mapPMD.put(cwe, list);
                    }
                    Rule issue = new Rule(cwe, fileJ, l);
                    // Check se la lista non contiene già quella rule
                    int ruleIsInList = 0;
                    System.out.println(mapPMD.get(cwe).size());
                    for (Rule rule: mapPMD.get(cwe)){
                        if(rule.getFile().equals(issue.getFile()) && rule.getRule().equals(issue.getRule()) && rule.getBug().equals(issue.getBug()) ){
                            ruleIsInList=1;
                            break;
                        }
                    }
                    if (ruleIsInList==0) {
                        mapPMD.get(cwe).add(issue);
                    }
                    mappingCweRuleExists = 1;
                }
            }
            if (mappingCweRuleExists == 0){
                if (!mapPMD.containsKey(r)){
                    List<Rule> list = new ArrayList<>();
                    mapPMD.put(r, list);
                }
                Rule issue = new Rule(r, fileJ, l);

                int f = 0;
                for (Rule rule: mapPMD.get(r)){
                    if(rule.getFile().equals(issue.getFile()) && rule.getRule().equals(issue.getRule()) && rule.getBug().equals(issue.getBug()) ){
                        f=1;
                        break;
                    }
                }
                if (f==0) {
                    mapPMD.get(r).add(issue);
                }
                //mapPMD.get(r).add(issue);

                //System.err.println(issue.getRule());
            }
        }
    }




    /*
    Save information file.java; cwe into fileName
     */
    public static void SaveCwe(String fileName, Map<String, List<Rule>> map) throws FileNotFoundException {

        ArrayList<Rule> rules = new ArrayList<>();
        PrintWriter writer = new PrintWriter(fileName);
        int s = map.entrySet().size();
        int j=0;
        for(Map.Entry<String, List<Rule>> entry : map.entrySet()) {
            System.out.println(j+"di: "+s);
            j+=1;
            String cwe = entry.getKey();

            System.out.println(entry.getValue().size());

            for(int i=0; i<entry.getValue().size(); i++) {
                String file = entry.getValue().get(i).getFile();

                String line = entry.getValue().get(i).getBug();

                // rule, file, bug
                StringBuilder sb = new StringBuilder();
                sb.append(file);
                sb.append(";");
                if (line.equals("no"))
                    sb.append("no");
                else
                    sb.append(cwe);
                sb.append(";");
                sb.append(line);
                sb.append('\n');
                writer.write(sb.toString());
                writer.flush();

            }
        }
    }
}