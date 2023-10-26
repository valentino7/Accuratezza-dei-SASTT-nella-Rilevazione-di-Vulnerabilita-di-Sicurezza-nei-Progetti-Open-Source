package controller;

import entity.Rule;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import utils.Constants;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static IO.ReaderInputs.getAbsolute;
import static common.StringCommon.removeBom;

public class CreateMappings {

    public static String outputMapping = getAbsolute(Constants.MAPPING_CWE_SNYK);
    public static String sourcePath = getAbsolute(Constants.REPORT_RESULTS);

    public static String snyk = sourcePath + "\\snyk";
    public static HashMap<String, Rule> hSnyk = new HashMap<>(); //Rule <rule:file.java>

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws IOException, ParseException {
        createMappingSnyk();
    }

    public static void createMappingSnyk() throws IOException, ParseException {
        String[] files = new File(snyk).list();

        for (String file : files) {
            // System.out.println("NOME FILE: " + file);
            Path path = Paths.get(snyk+"/"+file);
            removeBom(path);

            combineInformation(file, snyk+"/"+file, hSnyk);
        }
        saveMapping(outputMapping, hSnyk);

    }

    public static void saveMapping(String path, HashMap<String, Rule> map) throws FileNotFoundException {
        PrintWriter writer = new PrintWriter(path);
        String header = "<mappings scanner=\"SNYK\">\n";
        StringBuilder sbstart = new StringBuilder();
        sbstart.append(header);
        writer.write(sbstart.toString());
        writer.flush();

        for(Map.Entry<String, Rule> entry : map.entrySet()) {
            String line = "\t<scannerCode desc="+"\""+entry.getValue().getFile()+"\""+" name="+"\""+entry.getValue().getRule()+"\""+">\n";
            //System.out.println(line);
            String cwe = "\t\t<cwe>"+entry.getValue().getBug().split("-")[1]+"</cwe>\n";
            String endLine = "\t</scannerCode>\n";

            StringBuilder sb = new StringBuilder();
            sb.append(line);
            sb.append(cwe);
            sb.append(endLine);
            writer.write(sb.toString());
            writer.flush();
        }

        String ends = "</mappings>";
        StringBuilder sbEnd = new StringBuilder();
        sbEnd.append(ends);
        writer.write(sbEnd.toString());
        writer.flush();
    }




    public static void combineInformation(String filename, String completePath, HashMap<String, Rule> l) throws IOException, ParseException {
        JSONParser jsonParser = new JSONParser();

        FileReader reader = new FileReader(completePath);
        //Read JSON file
        try {
            Object obj = jsonParser.parse(reader);
            JSONObject bugList = (JSONObject) obj;

            Object completeRun = bugList.get("runs");

            JSONArray completeRunArray = (JSONArray) completeRun;
            completeRunArray.forEach(emp -> parseTestData((JSONObject) emp, l));
        }catch(Exception e){
            System.err.println(filename);
        }
    }

    private static void parseTestData(JSONObject emp, HashMap<String, Rule> l) {
        Object rules = ((JSONObject) ((JSONObject) emp.get("tool")).get("driver")).get("rules");
        JSONArray rulesArray = (JSONArray) rules;
        rulesArray.forEach( rule -> takeMapping( (JSONObject) rule, l ) );
    }

    private static void takeMapping(JSONObject emp, HashMap<String, Rule> l) {
        String name = (String) emp.get("name");
        JSONObject prop =  (JSONObject)emp.get("properties");

        JSONArray cwes = (JSONArray)((JSONObject) emp.get("properties")).get("cwe");
        String text = (String)((JSONObject) emp.get("shortDescription")).get("text");

        try{
            for (Object o : cwes){
                l.put(o.toString()+text+name, new Rule(name, text, o.toString()) );
            }
        }catch (Exception e){
        }
    }

}

