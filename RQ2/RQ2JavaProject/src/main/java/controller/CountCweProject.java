package controller;

import entity.VulasEntry;
import IO.ReaderInputs;
import utils.Constants;
import org.apache.commons.io.FileUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static IO.ReaderInputs.getAbsolute;

public class CountCweProject {


    public static void writeNewVulasDB(String path, ArrayList<VulasEntry> vulasEntriesWithoutNOValidCVE) throws IOException {

        Writer writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(new File(path)), StandardCharsets.UTF_8));

        for (VulasEntry v: vulasEntriesWithoutNOValidCVE){
            for (String s: v.getCveids()){
                writer.write(s + ";" + v.getProjectUrl() + ";"+v.getCommitID()+";"+"pos"+System.lineSeparator());
            }
        }
        writer.flush();
        writer.close();
    }

    public static void writeCWEList(String path, HashMap<String, VulasEntry> h) throws IOException {
        ArrayList<String> tmp = new ArrayList<>();

        for (Map.Entry<String, VulasEntry> set : h.entrySet()){
            tmp.add(set.getKey());
        }
        File file = new File(getAbsolute(path));
        FileUtils.writeLines(file, tmp, false);

        /*
        File file = new File(path);
        try {
            // create FileWriter object with file as parameter
            FileWriter outputfile = new FileWriter(file);

            // create CSVWriter object filewriter object as parameter
            CSVWriter writer = new CSVWriter(outputfile);

            // adding header to csv
            // CWE ID, Method ID (File$Method$FixCommitID), Badness (Yes/No), Tool ID, Size, CWE Result (predicted), opensource(Y/N)
            // 30, xxx, Yes, SQ, 4000, 40, Yes
            String[] header = { "CWE-ID" };
            writer.writeNext(header);

            for (Map.Entry<String, VulasEntry> set : h.entrySet()){
                writer.(set.getKey());
            }

            // closing writer connection
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }*/

    }




    public static HashMap<String, String> readCWETxt(String path) throws IOException {
        String line = "";

        HashMap<String, String> mapCVECWE = new HashMap<>();
        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            mapCVECWE.put(line, line);
        }
        return mapCVECWE;
    }

    public static void main(String args[]) throws IOException {

        // CVE CWE
        HashMap<String, String> mappingCve = ReaderInputs.readMappingCsv(Constants.PATH_MAPPING_CVE);
        System.out.println(mappingCve.size());
        ArrayList<VulasEntry> vulasEntries = ReaderInputs.readVulasCsv(Constants.PATH_VULAS_DB);
        ArrayList<VulasEntry> vulasEntriesWithoutNOValidCVE = new ArrayList<>();
        HashMap<String, VulasEntry> h = new HashMap<>();
        Integer count = 0;
        Integer filterCount = 0;
        for (VulasEntry v: vulasEntries){
            int validCVE = 0;
            ArrayList<String> filteredCVEList = new ArrayList<>();

            if(v.getCveids().size()>1) {
                System.err.println("NO");
                System.out.println(v.getCveids());
            }
            for (String s: v.getCveids()) {
                count+=1;
                if(!mappingCve.get(s).equals("NVD-CWE-Other") && !mappingCve.get(s).equals("NVD-CWE-noinfo") && !mappingCve.get(s).equals("None")){
                    filterCount+=1;
                    filteredCVEList.add(s);
                }
                h.put(mappingCve.get(s), v);
            }
            if ( !filteredCVEList.isEmpty()) {
                vulasEntriesWithoutNOValidCVE.add(v);
                v.setCveids(filteredCVEList);
            }
        }
        System.out.println(h.size());
        System.out.println("Size elementi con tutti cwe= "+String.valueOf(count));
        System.out.println("Size elementi con 67 cwe= "+String.valueOf(filterCount));
        //ArrayList<String> projectsCompilable = ReaderInputs.readCompileCsv(Constants.PATH_COMPILE, vulasEntries, "ALL");
        writeCWEList(Constants.ROOT_ANALISI+"cweList2.csv", h);
        System.exit(1);
        //writeNewVulasDB("F:\\Valentino\\IdeaProjects\\tesiJava\\src\\main\\result\\cweStats\\vulas_db_without_invalid_cve.csv", vulasEntriesWithoutNOValidCVE);

        //////////////////////QUANTI CWE RILEVATI DA SNYK POSSIEDO?\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
        HashMap<String, String> filteredCwe = readCWETxt(Constants.ROOT_ANALISI+"filteredCweList");
        HashMap<String, String> SnykCwe = readCWETxt(Constants.ROOT_ANALISI+"SnykCWE.txt");

        HashMap<String, VulasEntry> merge = new HashMap<>();

        for (Map.Entry<String, String> set : SnykCwe.entrySet()){
            if (filteredCwe.containsKey(set.getKey()))
                merge.put(set.getKey(), new VulasEntry());
        }
        System.out.println("CWE DI SNYK CHE SONO PRESENTI NELLA MIA LISTA DI CWE: "+ String.valueOf(merge.size()));

        writeCWEList(Constants.ROOT_ANALISI+"CWEPresentiInSnyk.csv", merge);


        // CHE PERCENTUALE DEL DATASET VULAS COPRO?
        HashMap<String,String> cwes = new HashMap<>();
        int percentageSnyk = 0;
        for (VulasEntry v: vulasEntries){
            for (String s: v.getCveids()) {
                cwes.put(mappingCve.get(s), "");
                if(!mappingCve.get(s).equals("NVD-CWE-Other") && !mappingCve.get(s).equals("NVD-CWE-noinfo") && !mappingCve.get(s).equals("None")) {
                    if (merge.containsKey("\""+mappingCve.get(s)+"\""))
                        percentageSnyk += 1;
                }
            }
        }
        System.out.println("NUMERO RIGHE DI VULAS COPERTE DA SNYK: "+ String.valueOf(percentageSnyk));


    }
}
