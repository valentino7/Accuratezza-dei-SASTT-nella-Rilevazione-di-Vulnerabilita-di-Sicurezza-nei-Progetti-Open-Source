package controller;

import IO.ReaderInputs;
import com.opencsv.CSVWriter;
import entity.FileTrack;
import entity.Rule;
import org.apache.maven.shared.utils.StringUtils;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import utils.Constants;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import static IO.ReaderInputs.getAbsolute;

public class CreateFinalDataset {

    public static void SavePMD(String fileName, ArrayList<Rule> rules) throws FileNotFoundException {

        PrintWriter writer = new PrintWriter(fileName);
        for(Rule r: rules) {

            StringBuilder sb = new StringBuilder();
            sb.append(r.getFile());
            sb.append(";");
            sb.append(r.getRule());
            sb.append(";");
            sb.append(r.getBug());
            sb.append('\n');
            writer.write(sb.toString());
            writer.flush();
        }
    }

    public static HashMap<String, String> read_mapper(String path)throws IOException{
        String line = "";
        String splitBy = ",";

        HashMap<String, String> mapping = new HashMap<>();
        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));
        int count=0;
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            String[] l = line.split(splitBy);    // use comma as separator
            mapping.put(l[0].substring(1), l[1].substring(0,l[1].length()-1));

        }
        return mapping;

    }

    public static void main(String args[]) throws IOException, GitAPIException, InterruptedException, ClassNotFoundException, XmlPullParserException {
        /*
            Read Input
         */

        /*ArrayList<Rule> rulesSpotbugs = ReaderInputs.readPluginResults(Constants.PATH_SPOTBUGS_RESULT);
        ArrayList<Rule> rulesJlint = ReaderInputs.readPluginResults(Constants.PATH_JLINT_RESULT);
        ArrayList<Rule> rulesFindsec = ReaderInputs.readPluginResults(Constants.PATH_FINDSEC_RESULT);*/
        //SavePMD("F:\\Valentino\\IdeaProjects\\tesiJava\\src\\main\\result\\parsingToolResult\\uniquefilePMD.csv",rulesPmd);
        ArrayList<FileTrack> files = ReaderInputs.readIntermediateResults(Constants.INTERMEDIATE_PATH_RESULT);
        System.out.println("Fine letture intermediate");
        runWithoutBlocks(files);

    }
    public static void runWithoutBlocks(ArrayList<FileTrack> files) throws IOException {

        //Scorro i result
        // per ogni metodo scorro tutti i tool e vedo se è contenuto (jlint e snyk richiedono un cofronto per size)
        // ricreo la struttura hfiletrack
        // scrittura finale

        ArrayList<FileTrack> resultSnyk = new ArrayList();
        ArrayList<FileTrack> resultVcg = new ArrayList();
        ArrayList<FileTrack> resultPmd = new ArrayList();
        // Lettura parsingToolResult
        //ArrayList<Rule> rulesSnyk = ReaderInputs.readPluginResults(Constants.PATH_SNYK_PARSING_REPORT);
        //ArrayList<Rule> rulesSnyk = ReaderInputs.readPluginResults("src\\main\\java\\resources\\ParsingToolResult\\fileTagliatoSnyk.csv");
        ArrayList<Rule> rulesSnyk = ReaderInputs.readPluginResults(getAbsolute(Constants.PATH_SNYK_PARSING_REPORT));

        ArrayList<Rule> rulesVcg = ReaderInputs.readPluginResults(getAbsolute(Constants.PATH_VCG_PARSING_REPORT));
        ArrayList<Rule> rulesPmd = ReaderInputs.readPluginResults(getAbsolute(Constants.PATH_PMD_PARSING_REPORT));
        System.out.println("fine lettura sasstt");
        // Leggi mapper path
        HashMap<String, String> mapper_path = read_mapper(getAbsolute(Constants.PATH_MAPPING_PATH));

        for (FileTrack f : files) {
            /**
             * f è il file track preso dal fine intermediate che contiene tutti i metodi delle commit
             * rules è l'array dei plugin da scorrere per trovare il match con il metodo contenuto in f
             * result è l'array da riempire
             */
            /*checkJlint(f, rulesJlint, result);
            checkSpotbugs(f, rulesSpotbugs, result);
            checkFindsec(f, rulesFindsec, result);
            checkPmd(f, rulesPmd, result);*/


            checkVCG(f, rulesVcg, resultVcg, mapper_path);
            checkSnyk(f, rulesSnyk, resultSnyk );
            checkPmd(f, rulesPmd, resultPmd, mapper_path);
        }
        saveOnCsv(getAbsolute(Constants.PATH_FINAL_RESULT) + "\\PMD.csv", resultPmd);
        saveOnCsv(getAbsolute(Constants.PATH_FINAL_RESULT) + "\\VCG.csv", resultVcg);
        saveOnCsv(getAbsolute(Constants.PATH_FINAL_RESULT) + "\\SNYK.csv", resultSnyk);

    }


    public static void saveOnCsv(String path, ArrayList<FileTrack> result){
        File file = new File(path);
        try {
            // create FileWriter object with file as parameter
            FileWriter outputfile = new FileWriter(file);

            // create CSVWriter object filewriter object as parameter
            CSVWriter writer = new CSVWriter(outputfile);

            // adding header to csv
            // CWE ID, Method ID (File$Method$FixCommitID), Badness (Yes/No), Tool ID, Size, CWE Result (predicted), opensource(Y/N)
            // 30, xxx, Yes, SQ, 4000, 40, Yes
            String[] header = { "CWE-ID", "Project Name", "Method-ID", "Fix Commit", "Badness", "Tool-ID", "Tool result", "Size", "TP", "TN", "FP", "FN"};
            writer.writeNext(header);

            for (FileTrack f : result){

                int s = f.gethMethodPosition().get("").getLineEnd()-f.gethMethodPosition().get("").getLineBegin();
                if (s==0)
                    s=1;
                String[] data = { f.getCWE(), f.getProjectName(), f.getFileName(),
                                  f.getFixCommitID(), f.getBadness().toString(),
                                  f.getTooldID(), f.getToolResult(), String.valueOf(s),
                                  f.getTp(), f.getTn(), f.getFp(), f.getFn()};
                writer.writeNext(data);
            }

            // closing writer connection
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean toolIsAbleToDetectCWE(String cwe, String tool) throws ParserConfigurationException, IOException, SAXException {
        if (tool.equals("snyk")){
            File fXmlFile = new File(Constants.MAPPING_CWE_SNYK);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(fXmlFile);
            NodeList nList = doc.getElementsByTagName("scannerCode");

            for (int temp = 0; temp < nList.getLength(); temp++) {
                Node nNode = nList.item(temp);
                Element eElement = (Element) nNode;
                String snykCweID = eElement.getElementsByTagName("cwe").item(0).getTextContent();

                if ( cwe.equals("CWE-"+snykCweID))
                    return true;
            }
        }else if(tool.equals("pmd")){
            File file = new File(getAbsolute(Constants.MAPPING_CWE_PMD));
            FileReader fr = new FileReader(file);
            BufferedReader br = new BufferedReader(fr);
            String line = " ";
            while ((line = br.readLine()) != null) {
                String tmpCwe = cwe.replace("-", ":");
                if (line.contains(tmpCwe)){
                    String pmdCwe = line.split(";")[0];
                    //String pmdCwe = parts[0].split(":")[1];
                    if(tmpCwe.equals(pmdCwe))
                        return true;
                }
            }
        }else if(tool.equals("vcg")){

            String[] vcgListCwe = {"CWE-327","CWE-614","CWE-89","CWE-78","CWE-643","CWE-22","CWE-330","CWE-79","CWE-501", "CWE-264", "CWE-668", "CWE-399", "CWE-20","CWE-190", "CWE-77", "CWE-502"};
            for (String s: vcgListCwe){
                if ( cwe.equals(s))
                    return true;
            }
        }
        return false;
    }

    //////////////////////////////////VCG//////////////////////////////////////////////////

    public static void checkVCG(FileTrack f, ArrayList<Rule> rules,ArrayList<FileTrack> result, HashMap<String, String> mapper){
        String methodName = f.getFileName().split("\\$")[1];


        // nome della classe java senza .java
        String classfilename = f.getFileName().split("\\$")[0].split("/")[f.getFileName().split("$")[0].split("/").length-1].split(".java")[0];

        FileTrack copy = new FileTrack();
        copy.setBadness(f.getBadness());
        copy.setCWE(f.getCWE());
        copy.setProjectName(f.getProjectName());
        copy.setFileName(f.getFileName());
        copy.setTooldID("vcg");
        copy.setParentCommit(f.getParentCommit());
        copy.setFixCommitID(f.getFixCommitID());
        copy.sethMethodPosition(f.gethMethodPosition());
        copy.setFp("False");
        copy.setTp("False");
        copy.setFn("False");
        copy.setTn("False");
        boolean found = false;
        ArrayList<String> vcgCweList = new ArrayList<>();

        String filename;
        if (!f.getBadness())
            filename = "good"+"$"+f.getFixCommitID()+"$"+classfilename;
        else
            filename = "bad"+"$"+f.getFixCommitID()+"$"+classfilename;

        try {


            if(! toolIsAbleToDetectCWE(f.getCWE(), "vcg")){
                copy.setToolResult("[??]");
                copy.setFn("??");
                copy.setFp("??");
                copy.setTp("??");
                copy.setTn("??");
                result.add(copy);
                return;
            }
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        }



        for (Rule r: rules){

            String[] lFileName = r.getFile().split("\\$");
            // i filename di vcg sono fatti cosi-> cwe$bad/good$fixcommit$progressivo da mappare$classe.java
            // CWE-1021_good_dbf259508c2b8e176d8cb837177aaadbf44f0670_JettyServer.java;190;691
            String rFileName = lFileName[1]+"$"+lFileName[2]+"$"+lFileName[4];

            rFileName=rFileName.substring(0, rFileName.length()-5);

            String progressivo = lFileName[3];
            String cwe = lFileName[0];
            //indice map -> CWE-22\3
            String indiceMap = cwe+"\\"+progressivo;
            String resultvcgPath = mapper.get(indiceMap);

            String intermediatePath = f.getFileName();
            intermediatePath = intermediatePath.split("\\$")[0];
            intermediatePath = intermediatePath.replace(classfilename,"").replace(".java","").replace("/","");

            if(f.gethMethodPosition().get("").getLineBegin()<=Integer.valueOf(r.getBug())
                    && f.gethMethodPosition().get("").getLineEnd() >= Integer.valueOf(r.getBug()) &&
                    filename.equals(rFileName) &&  intermediatePath.equals(resultvcgPath)){


                if (!f.getBadness()){
                    // File Fixed
                    if (f.getCWE().equals("CWE-"+r.getRule())){
                        copy.setFp("True");
                    }
                }else{
                    // File Bad
                    if (f.getCWE().equals("CWE-"+r.getRule())){
                        copy.setTp("True");
                    }
                }

                vcgCweList.add(r.getRule());
                found = true;
            }
        }

        if (found == false){
            vcgCweList.add("");
            if (!f.getBadness()){
                copy.setTn("True");
            }else{
                copy.setFn("True");
            }
        }

        else if( found == true){
            if (!f.getBadness()) {
                if (copy.getFp().equals("False"))
                    copy.setTn("True");
            }else{
                if (copy.getTp().equals("False"))
                    copy.setFn("True");
            }
        }

        String[] unique = Arrays.stream(vcgCweList.toArray()).distinct().toArray(String[]::new);
        ArrayList<String> tmp = new ArrayList<>();
        for (String s: unique){
            tmp.add(s);
        }
        copy.setToolResult(tmp.toString());
        result.add(copy);
    }


    ////////////////////////////////////PMD/////////////////////////////////////////////////////

    public static void checkPmd(FileTrack f, ArrayList<Rule> rules,ArrayList<FileTrack> result, HashMap<String, String> mapper){
        FileTrack copy = new FileTrack();
        copy.setProjectName(f.getProjectName());
        copy.setBadness(f.getBadness());
        copy.setCWE(f.getCWE());
        copy.setFileName(f.getFileName());
        copy.setTooldID("pmd");
        copy.setParentCommit(f.getParentCommit());
        copy.setFixCommitID(f.getFixCommitID());
        copy.sethMethodPosition(f.gethMethodPosition());
        copy.setFp("False");
        copy.setTp("False");
        copy.setFn("False");
        copy.setTn("False");
        boolean found = false;
        ArrayList<String> pmdFoundCweList = new ArrayList<>();


        String methodName = f.getFileName().split("\\$")[1];
        String classfilename = f.getFileName().split("\\$")[0].split("/")[f.getFileName().split("\\$")[0].split("/").length-1].split(".java")[0];

        String filename ;
        if (!f.getBadness())
            filename = "good"+"$"+f.getFixCommitID()+"$"+classfilename;
        else
            filename = "bad"+"$"+f.getFixCommitID()+"$"+classfilename;

        try {
            /**
             *             Il tool può rilevare il CWE ?
             *             Sì proseguo il flusso
             *             No termino settando ?? le metriche
             */

            if(! toolIsAbleToDetectCWE(f.getCWE(), "pmd")){
                copy.setToolResult("??");
                copy.setFn("??");
                copy.setFp("??");
                copy.setTp("??");
                copy.setTn("??");
                result.add(copy);
                return;
            }
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        }

        for (Rule r: rules) {
            String[] lFileName = r.getFile().split("\\$");

            // lFileName = bad$515c822148d52de9e7cdf4f6b01f7b793f2f273f$17$NomeFile
            String rFileName = lFileName[1] + "$" + lFileName[2] + "$" + lFileName[4];


            String progressivo = lFileName[3];
            String cwe = lFileName[0];
            //indice map -> CWE-22\3
            System.out.println(cwe);
            System.out.println(progressivo);
            String indiceMap = cwe + "\\" + progressivo;
            String resultpmdPath = mapper.get(indiceMap);

            String intermediatePath = f.getFileName();
            intermediatePath = intermediatePath.split("\\$")[0];
            intermediatePath = intermediatePath
                    .replace(classfilename, "")
                    .replace(".java", "")
                    .replace("/", "");

            /*if (methodName.equals("readRequest") && r.getBug().equals("readRequest") && intermediatePath.equals("componentscamel-http-commonsrcmainjavaorgapachecamelhttpcommon") && resultpmdPath.equals("componentscamel-http-commonsrcmainjavaorgapachecamelhttpcommon")){
                System.out.println(r.getBug());
                System.out.println(methodName);

                System.out.println(filename);
                System.out.println(rFileName);
                System.exit(1);
            }*/
            if(methodName.equals(r.getBug()) && filename.equals(rFileName) && intermediatePath.equals(resultpmdPath)){
                if (!f.getBadness()){
                    // File Fixed
                    if (f.getCWE().equals("CWE-"+r.getRule())){
                        copy.setFp("True");
                    }
                }else{
                    // File Bad
                    if (f.getCWE().equals("CWE-"+r.getRule())){
                        copy.setTp("True");
                    }
                }

                pmdFoundCweList.add(r.getRule());
                found = true;
            }
        }
/**
 *         Il tool rimane in silenzio - Viene fatta la distinzione tra file fixed e bad
 */
        if (found == false){
            pmdFoundCweList.add("");
            if (!f.getBadness()){
                copy.setTn("True");
            }else{
                copy.setFn("True");
            }
        }
        /**
         *         Se invece il tool risponde in maniera sbagliata - Viene fatta la distinzione tra file fixed e bad
         */
        else if( found == true){
            if (!f.getBadness()) {
                if (copy.getFp().equals("False"))
                    copy.setTn("True");
            }else{
                if (copy.getTp().equals("False"))
                    copy.setFn("True");
            }
        }

        String[] unique = Arrays.stream(pmdFoundCweList.toArray()).distinct().toArray(String[]::new);
        ArrayList<String> tmp = new ArrayList<>();
        for (String s: unique){
            tmp.add(s);
        }
        System.out.println(tmp.toString());

        copy.setToolResult(tmp.toString());

        result.add(copy);
    }


    ///////////////////////////////////SNYK//////////////////////////////////////////////////////////////////
    public static void checkSnyk(FileTrack f, ArrayList<Rule> rules,ArrayList<FileTrack> result){

        // 0a702f116d8b670e03fa48afdf057f7c81b97f9f $ Questo/e/il/path/PBEFileProcessor;23;51
        String p=f.getFileName().split("\\$")[0].split("/")[f.getFileName().split("$")[0].split("/").length-1].split(".java")[0];

        String filenameWithoutDollar = f.getFileName().split("\\$")[0];
        String javaClass = filenameWithoutDollar.split("/")[filenameWithoutDollar.split("/").length-1];
        String  path= StringUtils.join(filenameWithoutDollar.replace(javaClass, "").split("/"),"");

        String filename = path+javaClass.replace(".java","").trim();
        FileTrack copy = new FileTrack();
        copy.setBadness(f.getBadness());
        copy.setCWE(f.getCWE());
        copy.setProjectName(f.getProjectName());
        copy.setParentCommit(f.getParentCommit());
        copy.setFileName(f.getFileName());
        copy.setTooldID("snyk");
        copy.setFixCommitID(f.getFixCommitID());
        copy.sethMethodPosition(f.gethMethodPosition());
        copy.setFp("False");
        copy.setTp("False");
        copy.setFn("False");
        copy.setTn("False");
        boolean found = false;
        ArrayList<String> snykList = new ArrayList<>();


        if (!f.getBadness()) {
            filename = f.getFixCommitID() + "$" + filename;
        }else {
            filename = f.getParentCommit() + "$" + filename;
        }


        try {
            /**
             *             Il tool può rilevare il CWE ?
             *             Sì proseguo il flusso
             *             No termino settando ?? le metriche
             */
            if(! toolIsAbleToDetectCWE(f.getCWE(), "snyk")){
                copy.setToolResult("??");
                copy.setFn("??");
                copy.setFp("??");
                copy.setTp("??");
                copy.setTn("??");
                result.add(copy);
                return;
            }
        } catch (Exception e) {
            System.out.println("TOOL IS ABLE TO");
            e.printStackTrace();
            System.exit(1);
        }

        try {

            for (Rule r : rules) {
                // r.getFile() contiene il nome della classe senza il .java

                String ruleFilenameReplaced = r.getFile().replace("/","");
                if (f.gethMethodPosition().get("").getLineBegin() <= Integer.valueOf(r.getBug())
                        && f.gethMethodPosition().get("").getLineEnd() >= Integer.valueOf(r.getBug())
                        && filename.equals(ruleFilenameReplaced)) { //&& f.getCWE().equals("CWE-"+r.getRule())){
                    System.out.println(filename);
                    System.out.println(r.getFile());
                    System.out.println(f.gethMethodPosition().get("").getLineEnd());
                    System.out.println(f.gethMethodPosition().get("").getLineBegin());


                    if (!f.getBadness()) {
                        // File Fixed
                        if (f.getCWE().equals("CWE-" + r.getRule())) {
                            copy.setFp("True");
                        }
                    } else {
                        // File Bad
                        if (f.getCWE().equals("CWE-" + r.getRule())) {
                            copy.setTp("True");
                        }
                    }

                    snykList.add(r.getRule());
                    found = true;
                }
            }
            /**
             *         Il tool rimane in silenzio - Viene fatta la distinzione tra file fixed e bad
             */
            if (found == false) {
                snykList.add("");
                if (!f.getBadness()) {
                    copy.setTn("True");
                } else {
                    copy.setFn("True");
                }
            }
            /**
             *         Se invece il tool risponde in maniera sbagliata - Viene fatta la distinzione tra file fixed e bad
             */
            else if (found == true) {
                if (!f.getBadness()) {
                    if (copy.getFp().equals("False"))
                        copy.setTn("True");
                } else {
                    if (copy.getTp().equals("False"))
                        copy.setFn("True");
                }
            }
            String[] unique = Arrays.stream(snykList.toArray()).distinct().toArray(String[]::new);
            ArrayList<String> tmp = new ArrayList<>();
            for (String s: unique){
                tmp.add(s);
            }

            copy.setToolResult(tmp.toString());
            result.add(copy);

        }catch (Exception e){
            System.out.println("secondo try");

            e.printStackTrace();
            System.exit(1);
        }
    }
















    public static void checkFindsec(FileTrack f, ArrayList<Rule> rules,ArrayList<FileTrack> result){
        String methodName = f.getFileName().split("\\$")[1];
        String filename = f.getFileName().split("\\$")[0].split("/")[f.getFileName().split("$")[0].split("/").length-1].split(".java")[0];
        if (!f.getBadness())
            filename = "good"+"_"+f.getFixCommitID().substring(0, 8)+"_"+filename+".xml";
        else
            filename = "bad"+"_"+f.getFixCommitID().substring(0, 8)+"_"+filename+".xml";

        FileTrack copy = new FileTrack();
        copy.setBadness(f.getBadness());
        copy.setCWE(f.getCWE());
        copy.setFileName(f.getFileName());
        copy.setTooldID("findsec");
        copy.setParentCommit(f.getParentCommit());
        copy.setFixCommitID(f.getFixCommitID());
        copy.sethMethodPosition(f.gethMethodPosition());
        copy.setToolResult("true");
        for (Rule r: rules){
            String[] lFileName = r.getFile().split("_");
            String rFileName = lFileName[1]+"_"+lFileName[2]+"_"+lFileName[3];
            if(methodName.equals(r.getBug()) && filename.equals(rFileName) && f.getCWE().equals("CWE-"+r.getRule())){
                copy.setToolResult("false");
            }
        }
        result.add(copy);

    }

    public static void checkSpotbugs(FileTrack f, ArrayList<Rule> rules,ArrayList<FileTrack> result){
        String methodName = f.getFileName().split("\\$")[1];
        String filename = f.getFileName().split("\\$")[0].split("/")[f.getFileName().split("$")[0].split("/").length-1].split(".java")[0];
        if (!f.getBadness())
            filename = "good"+"_"+f.getFixCommitID().substring(0, 8)+"_"+filename+".xml";
        else
            filename = "bad"+"_"+f.getFixCommitID().substring(0, 8)+"_"+filename+".xml";
        FileTrack copy = new FileTrack();
        copy.setBadness(f.getBadness());
        copy.setCWE(f.getCWE());
        copy.setFileName(f.getFileName());
        copy.setTooldID("spotbugs");
        copy.setParentCommit(f.getParentCommit());
        copy.setFixCommitID(f.getFixCommitID());
        copy.sethMethodPosition(f.gethMethodPosition());
        copy.setToolResult("true");
        for (Rule r: rules){
            String[] lFileName = r.getFile().split("_");
            String rFileName = lFileName[1]+"_"+lFileName[2]+"_"+lFileName[3];
            if(methodName.equals(r.getBug()) && filename.equals(rFileName) && f.getCWE().equals("CWE-"+r.getRule())){
                copy.setToolResult("false");
            }
        }
        result.add(copy);
    }


    public static void checkJlint(FileTrack f, ArrayList<Rule> rules,ArrayList<FileTrack> result){
        String filename = f.getFileName().split("\\$")[0].split("/")[f.getFileName().split("$")[0].split("/").length-1].split(".java")[0];
        if (!f.getBadness())
            filename = "good"+"_"+f.getFixCommitID().substring(0, 8)+"_"+filename;
        else
            filename = "bad"+"_"+f.getFixCommitID().substring(0, 8)+"_"+filename;


        FileTrack copy = new FileTrack();
        copy.setBadness(f.getBadness());
        copy.setCWE(f.getCWE());
        copy.setParentCommit(f.getParentCommit());
        copy.setFileName(f.getFileName());
        copy.setTooldID("jlint");
        copy.setFixCommitID(f.getFixCommitID());
        copy.sethMethodPosition(f.gethMethodPosition());
        copy.setToolResult("true");
        for (Rule r: rules){
            String[] lFileName = r.getFile().split("_");
            String rFileName = lFileName[1]+"_"+lFileName[2]+"_"+lFileName[3];
            if(f.gethMethodPosition().get("").getLineBegin()<Integer.valueOf(r.getBug()) && f.gethMethodPosition().get("").getLineEnd() > Integer.valueOf(r.getBug()) && filename.equals(rFileName) && f.getCWE().equals("CWE-"+r.getRule())){
                copy.setToolResult("false");
            }
        }
        result.add(copy);
    }
}