package IO;

import entity.FileTrack;
import entity.GitInfo;
import entity.Rule;
import entity.VulasEntry;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;

public class ReaderInputs {

    public static void startProcess(ProcessBuilder processBuilder){
        try {
            Process process = processBuilder.start();
            String line = null;
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = bufferedReader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException ignored) {
            System.err.println("!**errore**!");
            ignored.printStackTrace();
        }
    }

    public static ArrayList<FileTrack> readIntermediateResults(String path) throws IOException {
        String line = "";
        String splitBy = ",";

        ArrayList<FileTrack> rules = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));
        int size = 0;
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            if (size == 0) {
                size += 1;
                continue;
            }
            String[] l = line.split(splitBy);    // use comma as separator

            // Possono esserci casi in cui compaiono piu cwe
            String cwes = l[0].substring(1, l[0].length() - 1);
            String[] cwesList = cwes.split("_");
            if(cwes.contains("_"))
                System.out.println(cwes);
            for (String cwe: cwesList) {
                FileTrack f = new FileTrack();
                f.setCWE(cwe);
                f.setProjectName(l[1].substring(1, l[1].length() - 1));

                f.setFileName(l[2].substring(1, l[2].length() - 1));
                f.setFixCommitID(l[3].substring(1, l[3].length() - 1));
                f.setParentCommit(l[4].substring(1, l[4].length() - 1));
                if (l[5].substring(1, l[5].length() - 1).equals("true"))
                    f.setBadness(true);
                else
                    f.setBadness(false);
                f.setTooldID(l[6].substring(1, l[6].length() - 1));
                HashMap<String, GitInfo> h = new HashMap<String, GitInfo>();
                h.put("", new GitInfo(Integer.valueOf(l[8].substring(1, l[8].length() - 1)), Integer.valueOf(l[9].substring(1, l[9].length() - 1))));
                f.sethMethodPosition(h);
                rules.add(f);
            }
        }
        return rules;
    }

    public static long getNumLines(String path) throws FileNotFoundException {
            String line = "";
            String splitBy = ";";

            ArrayList<Rule> rules = new ArrayList<Rule>();
            BufferedReader br1 = new BufferedReader(new FileReader(getAbsolute(path)));
            long nLines = br1.lines().count();
            return nLines;
    }
    public static ArrayList<Rule> readPluginResultsBlock(String path, long lineStart, long lineEnd) throws IOException {
        String line = "";
        String splitBy = ";";

        ArrayList<Rule> rules = new ArrayList<Rule>();

        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));


        int i=0;
        System.out.println(lineEnd);
        System.out.println(lineStart);
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {

            if (i>= lineStart && i < lineEnd) {
                String[] l = line.split(splitBy);    // use comma as separator

                // rule, file, bug
                Rule r = new Rule(l[1], l[0], l[2]);

                int found = 0;
                for (Rule tmp : rules) {
                    if (tmp.getFile().equals(l[0]) && tmp.getBug().equals(l[2]) && tmp.getRule().equals(l[1])) {
                        found = 1;
                        break;
                    }
                }
                if (found == 0)
                    rules.add(r);
            }
            i+=1;
        }
        return rules;
    }

    public static int existInList(ArrayList<Rule> rules, String l0, String l1, String l2){
        int found = 0;
        for (Rule tmp : rules) {
            if (tmp.getFile().equals(l0) && tmp.getBug().equals(l2) && tmp.getRule().equals(l1)) {
                found = 1;
                break;
            }
        }
        return found;
    }
    public static ArrayList<Rule> readPluginResults(String path) throws IOException {
        String line = "";
        String splitBy = ";";

        ArrayList<Rule> rules = new ArrayList<Rule>();

        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));
        int i=0;
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            System.out.println(i);
            i++;
            String[] l = line.split(splitBy);    // use comma as separator
            String predictedCwe = l[1];
            String methodOrLine = l[2];
            String id = l[0];
            String[] cwes;
            // rule, file, bug
            /**
             * 1) ad uno stesso metodo sono associati più cwe-id actual, è importante suddividere tali righe
             * 2) vcg associa piu cwe-id a uno stesso cwe-name, è importante suddividere tali righe
             */
            String[] filenameSplit = id.split("_");
            ArrayList<String> cwesActual = new ArrayList<>();
            if (filenameSplit.length > 4) {
                for (String tmp : filenameSplit) {
                    if (tmp.equals("bad") || tmp.equals("good"))
                        break;
                    cwesActual.add(tmp + "_" + filenameSplit[filenameSplit.length - 3] + "_" + filenameSplit[filenameSplit.length - 2] + "_" + filenameSplit[filenameSplit.length - 1]);
                }
            } else {
                cwesActual.add(id);
            }
            for (String cweActual : cwesActual) {
                if (predictedCwe.contains("_")) {
                    cwes = predictedCwe.split("_");
                    for (String c : cwes) {
                        Rule r = new Rule(c, cweActual, methodOrLine);
                        if (existInList(rules, cweActual, c, methodOrLine) == 0)
                            rules.add(r);
                    }
                } else {
                    Rule r = new Rule(predictedCwe, cweActual, methodOrLine);
                    if (existInList(rules, cweActual, predictedCwe, methodOrLine) == 0)
                        rules.add(r);
                }
            }
        }
        return rules;
    }

    public static String getAbsolute(String path){
        return new File(path).getAbsolutePath();
    }

    public static ArrayList<VulasEntry> readVulasCsv(String path) throws IOException {
        String line = "";
        String splitBy = ";";
        ArrayList<VulasEntry> vulasEntries = new ArrayList<VulasEntry>();
        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            String[] l = line.split(splitBy);    // use comma as separator
            int duplicate = 0;

            for (VulasEntry v : vulasEntries) {
                if (v.getProjectUrl().equals(l[1]) && v.getCommitID().equals(l[2])) {
                    duplicate = 1;
                    v.getCveids().add(l[0]);
                }
            }
            if (duplicate == 0){
                VulasEntry e = new VulasEntry();

                e.getCveids().add(l[0]);
                e.setProjectUrl(l[1]);
                e.setCommitID(l[2]);
                e.setCommand("");
                vulasEntries.add(e);

            }

        }
        return vulasEntries;
    }

    public static ArrayList<String>
    readAllCompileCsv(String path, ArrayList<VulasEntry> vulasEntries) throws IOException {
        String line = "";
        String splitBy = ";";

        ArrayList<String> projects = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));
        int count=0;
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            String[] l = line.split(splitBy);    // use comma as separator
            for (VulasEntry v : vulasEntries) {

                String name = v.getProjectUrl()+v.getCommitID();

                if (name.equals(l[0]+l[1])) {
                    v.setCommand(l[4]);
                    v.setJavaVersion(l[3]);
                    count+=1;
                    if (!projects.contains(l[0]))
                        projects.add(l[0]);

                }
            }
        }
        System.out.println("Numero commit compilabili contando i cve ripetuti: "+Integer.toString(count));
        System.out.println("Numero progetti senza contare le commit: "+ Integer.toString(projects.size()));

        int s=0;
        for (VulasEntry v : vulasEntries) {
            if (v.getCveids().size()>1 && !v.getCommand().equals(""))
                System.out.println(v.getCveids());
            if (!v.getCommand().equals(""))
                s++;
        }
        System.out.println("Numero commit compilabili NON contando i cve ripetuti: "+Integer.toString(s));
        System.out.println("\n\n");
        return projects;
    }

    public static HashMap<String, String> readMappingCommit(String path) throws IOException {
        String line = "";
        String splitBy = ",";

        HashMap<String, String> mappingCommit = new HashMap<>();
        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));
        int count=0;
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            String[] l = line.split(splitBy);    // use comma as separator
            mappingCommit.put(l[0].substring(1, l[0].length()-1),l[1].substring(1, l[1].length()-1));
        }
        return mappingCommit;
    }


    public static ArrayList<String>
    readCompileCsv(String path, ArrayList<VulasEntry> vulasEntries, String isCompilable) throws IOException {
        String line = "";
        String splitBy = ";";

        ArrayList<String> projects = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));
        int count=0;
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            String[] l = line.split(splitBy);    // use comma as separator
            if (l[2].equals(isCompilable)) {
                for (VulasEntry v : vulasEntries) {

                    String name = v.getProjectUrl()+v.getCommitID();

                    if (name.equals(l[0]+l[1])) {
                        v.setCommand(l[4]);
                        v.setJavaVersion(l[3]);
                        count+=1;
                        if (!projects.contains(l[0]))
                            projects.add(l[0]);

                    }
                }
            }
            if (isCompilable.equals("ALL")){
                for (VulasEntry v : vulasEntries) {

                    String name = v.getProjectUrl()+v.getCommitID();

                    if (name.equals(l[0]+l[1])) {
                        v.setCommand(l[4]);
                        v.setJavaVersion(l[3]);
                        count+=1;
                        if (!projects.contains(l[0]))
                            projects.add(l[0]);
                    }
                }
            }
        }
        System.out.println("Numero commit compilabili contando i cve ripetuti: "+Integer.toString(count));
        System.out.println("Numero progetti senza contare le commit: "+ Integer.toString(projects.size()));

        int s=0;
        for (VulasEntry v : vulasEntries) {
            if (v.getCveids().size()>1 && !v.getCommand().equals(""))
                System.out.println(v.getCveids());
            if (!v.getCommand().equals(""))
                s++;
        }
        System.out.println("Numero commit compilabili NON contando i cve ripetuti: "+Integer.toString(s));
        System.out.println("\n\n");
        return projects;
    }

    public static HashMap<String, String> readMappingCsv(String path) throws IOException {
        String line = "";
        String splitBy = ",";

        HashMap<String, String> mapCVECWE = new HashMap<>();
        BufferedReader br = new BufferedReader(new FileReader(getAbsolute(path)));
        while ((line = br.readLine()) != null)   //returns a Boolean value
        {
            String[] l = line.split(splitBy);    // use comma as separator
            mapCVECWE.put(l[0], l[1]);
        }
        return mapCVECWE;
    }


}
