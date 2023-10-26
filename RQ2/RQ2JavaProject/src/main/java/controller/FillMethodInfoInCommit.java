package controller;

import IO.ReaderInputs;
import IO.WriterResults;
import com.opencsv.CSVWriter;
import entity.FileTrack;
import entity.VulasEntry;
import org.apache.maven.model.Model;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.eclipse.jgit.api.errors.GitAPIException;
import utils.Constants;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static IO.ReaderInputs.getAbsolute;
import static IO.ReaderInputs.startProcess;

public class FillMethodInfoInCommit {

    public static void writeStatistic(String path1, String path2, HashMap<String, FileTrack> hFileTrackGit ){
        // Lista cwe che hanno le classi
        ArrayList<String> cwes = new ArrayList<>();
        for (Map.Entry<String, FileTrack> set : hFileTrackGit.entrySet()){
            cwes.add(set.getValue().getCWE());
        }
        System.out.println(cwes.size());

        Set<String> set = new HashSet<>(cwes);
        cwes.clear();
        cwes.addAll(set);
        System.out.println(cwes.size());

        File file = new File(getAbsolute(path1));
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

            for (String s: cwes){
                String[] data = {s};
                writer.writeNext(data);
            }

            // closing writer connection
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }

        // Numero elementi
        File file2 = new File(getAbsolute(path2));
        try {
            // create FileWriter object with file as parameter
            FileWriter outputfile = new FileWriter(file2);

            // create CSVWriter object filewriter object as parameter
            CSVWriter writer = new CSVWriter(outputfile);

            // adding header to csv
            // CWE ID, Method ID (File$Method$FixCommitID), Badness (Yes/No), Tool ID, Size, CWE Result (predicted), opensource(Y/N)
            // 30, xxx, Yes, SQ, 4000, 40, Yes
            String[] header = { "CWE-ID", "Project", "Commit" };
            writer.writeNext(header);

            for (Map.Entry<String, FileTrack> element : hFileTrackGit.entrySet()){
                if(element.getValue().getBadness().equals(false)) {
                    String[] data = {element.getValue().getCWE(), element.getValue().getProjectName(), element.getValue().getFixCommitID()};
                    writer.writeNext(data);
                }
            }

            // closing writer connection
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void compilationProject(String path, VulasEntry e) throws InterruptedException, IOException, XmlPullParserException {

        System.out.println("\n\n NUOVA COMPILAZIONE");

        System.out.println(e.getJavaVersion());
        ProcessBuilder processBuilder = new ProcessBuilder(); // pass in your command and options;
        HashMap<String, String> env = (HashMap<String, String>) processBuilder.environment();


        String tmp[] = env.get("Path").split(";");
        String p = "";
        String p1 = "";
        for (String t : tmp) {
            if (t.contains("jdk")) {
                env.put("Path", env.get("Path").replace(t, ""));
            }
            if(t.contains("maven")){
                env.put("Path", env.get("Path").replace(t, ""));

            }
        }
        //System.exit(1);
        //env.put("Path", env.get("Path").replace(p, "F:\\Valentino\\Java\\1.2\\bin"));
        env.put("Path", env.get("Path").replace("C:\\Program Files\\GitCommon Files\\Oracle\\Java\\javapath", ""));
        env.put("Path", env.get("Path").replace("C:\\Program Files (x86)\\GitCommon Files\\Oracle\\Java\\javapath", ""));

        if (e.getJavaVersion().contains("1.8")) {
            env.put("JAVA_HOME", "F:\\Valentino\\Java\\jdk1.8.0_211");
            env.put("Path", "F:\\Valentino\\Java\\jdk1.8.0_211\\bin"+";"+env.get("Path"));
        } else if (e.getJavaVersion().contains("19")) {
            env.put("JAVA_HOME", "F:\\Valentino\\Java\\jdk-19.0.1");
            env.put("Path", env.get("Path") + ";F:\\Valentino\\Java\\jdk-19.0.1\\bin");
        } else if (e.getJavaVersion().contains("17")) {
            env.put("JAVA_HOME", "F:\\Valentino\\Java\\jdk-17.0.4.1");
            env.put("Path", env.get("Path") + ";F:\\Valentino\\Java\\jdk-17.0.4.1\\bin");
        } else if (e.getJavaVersion().contains("11")) {
            System.err.println(11);
            env.put("JAVA_HOME", "F:\\Valentino\\Java\\jdk-11.0.16.1");
            env.put("Path", "F:\\Valentino\\apache-maven-3.8.6\\bin;F:\\Valentino\\Java\\jdk-11.0.16.1\\bin"+";"+env.get("Path"));
        } else if(e.getJavaVersion().contains("1.7")){
            System.err.println(1.7);
            env.put("JAVA_HOME", "C:\\Program Files\\Java\\jdk1.7.0_80");
            //env.put("Path", env.get("Path") + ";C:\\Program Files\\Java\\jdk1.7.0_80\\bin;F:\\Valentino\\maven-2.0.7\\bin");
            env.put("Path", "C:\\Program Files\\Java\\jdk1.7.0_80\\bin;F:\\Valentino\\apache-maven-2.2.1\\bin"+";"+env.get("Path") );
        } else if(e.getJavaVersion().contains("1.3")){
            env.put("JAVA_HOME", "C:\\jdk1.3.1_28");
            env.put("Path", env.get("Path") + ";C:\\jdk1.3.1_28\\bin");
        }else if(e.getJavaVersion().contains("1.4")){
            env.put("JAVA_HOME", "C:\\j2sdk1.4.2_19");
            env.put("Path", env.get("Path") + ";C:\\j2sdk1.4.2_19\\bin");
        }else if(e.getJavaVersion().contains("1.5")){
            env.put("JAVA_HOME", "C:\\Program Files (x86)\\Java\\jdk1.5.0_22");
            env.put("Path", env.get("Path") + ";C:\\Program Files (x86)\\Java\\jdk1.5.0_22\\bin");
        }
        env.put("Path", env.get("Path").replace(";;", ";"));
        env.put("Path", env.get("Path").replace(";;", ";"));

        System.out.println(env.get("Path"));
        System.out.println("\n\n");
        processBuilder.command("powershell", "echo", "$Env:JAVA_HOME",";","echo","$Env:Path",";","java","-version");
        processBuilder.redirectErrorStream(true);
        startProcess(processBuilder);
        System.out.println("\n");


        String lCmd[] = e.getCommand().split(" ");
        System.out.println("command: " + e.getCommand());
        if (e.getCommand().contains("mvn"))
            processBuilder.command("powershell", "CD", path,";","mvn","compile", "-e");
            //processBuilder.command("powershell", "CD", path, ";", lCmd[0], lCmd[1], "-U",  lCmd[2]);
        else if (e.getCommand().contains("gradle")) {
            //processBuilder.command("powershell", "CD", path, ";", lCmd[0], lCmd[1], "--stacktrace");
            processBuilder.command("powershell", "CD", path, ";", "./gradlew", "build", "--stacktrace");
        }else
            processBuilder.command("powershell", "CD", path, ";", lCmd[0], lCmd[1], "-v");

        e.setIsCompilable("");
        processBuilder.redirectErrorStream(true);
        int res = 0;
        try {
            Process process = processBuilder.start();
            String line = null;
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = bufferedReader.readLine()) != null) {
                System.out.println(line);
                if (line.contains("BUILD SUCCESS") || line.contains("BUILD SUCCESSFUL") )
                    res = 1;
                /*if (line.contains("ERROR") || line.contains("BUILD FAILED") || line.contains("BUILD FAILURE") || line.contains("Could not create the Java Virtual Machine") || line.contains("FAILURE: Build failed with an exception")) {
                    System.out.println("errore");
                    e.setIsCompilable("No");
                    e.setOutput("");
                    while ((line = bufferedReader.readLine()) != null) {
                        e.setOutput(e.getOutput().concat(line + " " ));
                    }
                }*/
            }
            if (res == 0){
                System.err.println("!**errore**!");
                e.setIsCompilable("No");
                e.setOutput("");
                while ((line = bufferedReader.readLine()) != null) {
                    e.setOutput(e.getOutput().concat(line + " " ));
                }
            }
            process.waitFor();
            process.destroy();
        } catch (IOException ignored) {
            System.out.println("errre");
            ignored.printStackTrace();
        }
        if (!e.getIsCompilable().equals("No"))
            e.setIsCompilable("Si");
    }




    public static void analyzePomJDK(VulasEntry v, String path, ConcurrentHashMap<String, String> result) throws IOException, XmlPullParserException {

        System.out.println("\n\n NUOVA ANALISI");

        String pomFilename = path + "\\pom.xml";
        System.out.println(pomFilename);
        File pom = new File(pomFilename);

        if (pom.exists()) {
            // do something
            MavenXpp3Reader mavenReader = new MavenXpp3Reader();
            FileReader reader = new FileReader(pomFilename);
            Model model = mavenReader.read(reader);
            try {
                for (Plugin p : model.getBuild().getPlugins()) {

                    if (p.getConfiguration().toString().contains("source")) {
                        //System.out.println("source "+ p.getConfiguration());
                        System.out.println(p.getConfiguration().toString().split("<source>")[1].split("</source>")[0]);
                        String javaV = p.getConfiguration().toString().split("<source>")[1].split("</source>")[0];
                        if (!javaV.equals("${java.version}") && !javaV.contains("$")) {
                            result.put(pomFilename + v.getCommitID(), javaV);
                            v.setPomJDKVersion(javaV);
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (!result.containsKey(pomFilename + v.getCommitID())) {
                try {
                    for (Plugin p : model.getBuild().getPluginManagement().getPlugins()) {

                        if (p.getConfiguration().toString().contains("source")) {
                            //System.out.println("source "+ p.getConfiguration());
                            System.out.println(p.getConfiguration().toString().split("<source>")[1].split("</source>")[0]);
                            String javaV = p.getConfiguration().toString().split("<source>")[1].split("</source>")[0];
                            if (!javaV.equals("${java.version}") && !javaV.contains("$")) {
                                result.put(pomFilename + v.getCommitID(), javaV);
                                v.setPomJDKVersion(javaV);
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
            if (!result.containsKey(pomFilename + v.getCommitID())) {
                if (model.getProperties().containsKey("source-version")) {
                    System.out.println(model.getProperties().getProperty("source-version"));
                    result.put(pomFilename + v.getCommitID(), model.getProperties().getProperty("source-version"));
                    v.setPomJDKVersion(model.getProperties().getProperty("source-version"));
                } else if (model.getProperties().containsKey("maven.compiler.source")) {
                    System.out.println(model.getProperties().getProperty("maven.compiler.source"));
                    result.put(pomFilename + v.getCommitID(), model.getProperties().getProperty("maven.compiler.source"));
                    v.setPomJDKVersion(model.getProperties().getProperty("maven.compiler.source"));
                } else if (model.getProperties().containsKey("java.version")) {
                    System.out.println(model.getProperties().getProperty("java.version"));
                    result.put(pomFilename + v.getCommitID(), model.getProperties().getProperty("java.version"));
                    v.setPomJDKVersion(model.getProperties().getProperty("java.version"));
                } else {
                    System.out.println(pomFilename);
                    result.put(pomFilename + v.getCommitID(), "non trovata");
                    v.setPomJDKVersion("Non trovata la versione");
                }
            }

            reader.close();
        } else {
            System.out.println("No Pom");
            result.put(pomFilename + v.getCommitID(), "non esiste il pom");
            v.setPomJDKVersion("Non esiste il pom");
        }
    }

    public static void addCweToHashmap(HashMap<String,String> cwecve, HashMap<String,String> mappingCve, VulasEntry v){
        for (String s: v.getCveids())
            cwecve.put(mappingCve.get(s), "");

    }

    public static void main(String args[]) throws IOException, GitAPIException, InterruptedException, ClassNotFoundException, XmlPullParserException {

        /*
            Read Input
         */
        String isCompilable="No";
        ArrayList<VulasEntry> vulasEntries = ReaderInputs.readVulasCsv(Constants.PATH_VULAS_DB);
        ArrayList<String> projectsCompilable = ReaderInputs.readCompileCsv(Constants.PATH_COMPILE, vulasEntries, "Si");
        HashMap<String, String> mappingCve = ReaderInputs.readMappingCsv(Constants.FILTER_PATH_MAPPING_CVE);

//////////////////////////////////////////////////////////////////////////////
        /*
         * revert alla commit fix
         * prendo i file toccati e la linea della modifica
         * cerco il nome del metodo a quella linea
         * revert alla commit precedente e faccio la stessa cosa
         * creo la struttura delle cartelle dei risultati
         * compilazione
         */

        // Mappa con Nome File e Informazioni del File
        HashMap<String, String> cwecve = new HashMap();
        HashMap<String, FileTrack> hFileTrackGit = new HashMap();
        ArrayList<VulasEntry> lStats = new ArrayList<>();
        //Ciclo sui progetti
        int size = 0;

        if (isCompilable.equals("Si")){
            for (String p : projectsCompilable) {
                System.out.println(p);
                String projectName = p.split("/")[p.split("/").length - 1];

                ArrayList<VulasEntry> lVulas = new ArrayList<>();

                String projectPath = "";
                // ATTENZIONE!! vulasEntries Contiene cveid Duplicati
                // TODO Aggiustare i path di output
                for (VulasEntry e : vulasEntries) {
                    if (e.getProjectUrl().equals(p) && !e.getCommand().equals("")) {
                        if (e.getProjectUrl().equals(p)) {

                            e.setFixCommit(e.getCommitID());

                            if (args[0].equals("1")) {
                                // Creazione file dei metodi
                                RunnerCreateDatasetCWEClass.run(e, projectName, mappingCve, hFileTrackGit);
                            } else {
                                // Compilazione
                                if (e.getCommitID().equals("246a6db1cad205ca9b6fca00c544ab7443ba202")) {
                                    e.setJavaVersion("1.8");

                                    projectPath = Constants.PATH_PROJECT_ROOT + projectName;
                                    size += 1;
                                    lVulas.add(e);
                                    //analyzePomJDK(e, projectPath + e.getCommitID(), resultJDK);
                                    compilationProject(projectPath + e.getCommitID(), e);
                                    System.err.println(projectPath);
                                }
                            }
                        }
                    }
                }
            }
        }else{

            for (VulasEntry e : vulasEntries) {
                String projectName = e.getProjectUrl().split("/")[e.getProjectUrl().split("/").length - 1];

                e.setFixCommit(e.getCommitID());

                // Creazione file dei metodi
                RunnerCreateDatasetCWEClass.run(e, projectName, mappingCve, hFileTrackGit);

            }
        }

        System.out.println("Numero cwe totali: "+Integer.toString(cwecve.size()));
        System.out.println(size);
        System.out.println(lStats.size());
        System.out.println("finiti");


/////////////////////////////////////////////////////////////////////////////////////////

        //Lancio tool
        //RunnerTools.run();


/////////////////////////////////////////////////////////////////////////////////////////
        /*
            Write Result
         */
        if(args[0].equals("1")) {
            WriterResults.writeOnCsv(Constants.INTERMEDIATE_PATH_RESULT, hFileTrackGit);
            writeStatistic(Constants.CWE_LIST_BY_JAVA_CLASS, Constants.VULAS_ROW_WITH__JAVA_CLASS_IN_COMMIT,hFileTrackGit);
        }else{
            System.out.println("");
            WriterResults.writeStatsCompile(Constants.STATS_RESULT, lStats);
        }
    }
}