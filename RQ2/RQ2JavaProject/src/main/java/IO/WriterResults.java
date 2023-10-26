package IO;

import entity.FileTrack;
import entity.GitInfo;
import entity.VulasEntry;
import com.opencsv.CSVWriter;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static IO.ReaderInputs.getAbsolute;

public class WriterResults {



    public static void printWriter(PrintWriter writer, String[] l){
        StringBuilder sb = new StringBuilder();
        sb.append(l[0]);
        sb.append(";");
        sb.append(l[1]);
        sb.append(";");
        sb.append(l[2]);
        sb.append('\n');
        writer.write(sb.toString());
        writer.flush();
    }

    public static void writeStatsSourceJDK(String sourceJdkResult, ConcurrentHashMap<String, String> result) throws IOException {
        Writer writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(new File(getAbsolute(sourceJdkResult))), StandardCharsets.UTF_8));
        result.forEach((key, value) -> {
            try {
                writer.write(key + ";" + value + System.lineSeparator());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        writer.flush();
        writer.close();
    }
    public static void writeStatsCompile(String path, ArrayList<VulasEntry> lStats){
        File file = new File(getAbsolute(path));
        try {
            // create FileWriter object with file as parameter
            FileWriter outputfile = new FileWriter(file);

            // create CSVWriter object filewriter object as parameter
            CSVWriter writer = new CSVWriter(outputfile);

            // adding header to csv
            // CWE ID, Method ID (File$Method$FixCommitID), Badness (Yes/No), Tool ID, Size, CWE Result (predicted), opensource(Y/N)
            // 30, xxx, Yes, SQ, 4000, 40, Yes
            String[] header = { "Project", "Fix Commit", "Compilable", "Version", "Command", "Output", "Pom JDK Version", "Fix Commit" };
            writer.writeNext(header);

            for (VulasEntry e : lStats){
                String[] data = { e.getProjectUrl(), e.getCommitID(), e.getIsCompilable(), e.getJavaVersion(), e.getCommand(), e.getOutput(), e.getPomJDKVersion(), e.getFixCommit()};
                writer.writeNext(data);
            }

            // closing writer connection
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void writeOnCsv(String path, HashMap<String, FileTrack> hFileTrackGit){
        File file = new File(getAbsolute(path));
        try {
            // create FileWriter object with file as parameter
            FileWriter outputfile = new FileWriter(file);

            // create CSVWriter object filewriter object as parameter
            CSVWriter writer = new CSVWriter(outputfile);

            // adding header to csv
            // CWE ID, Method ID (File$Method$FixCommitID), Badness (Yes/No), Tool ID, Size, CWE Result (predicted), opensource(Y/N)
            // 30, xxx, Yes, SQ, 4000, 40, Yes
            String[] header = { "CWE-ID","Project-Name", "Method-ID", "Fix Commit", "Parent Commit","Badness", "Size","Start","End" };
            writer.writeNext(header);

            for (Map.Entry<String, FileTrack> set : hFileTrackGit.entrySet()){
                for (Map.Entry<String, GitInfo>  p: set.getValue().gethMethodPosition().entrySet()){
                    String[] data = { set.getValue().getCWE(), set.getValue().getProjectName(), set.getValue().getFileName()+"$"+p.getKey(), set.getValue().getFixCommitID(), set.getValue().getParentCommit(), set.getValue().getBadness().toString(), String.valueOf(p.getValue().getLineEnd()-p.getValue().getLineBegin()),String.valueOf(p.getValue().getLineBegin()),String.valueOf(p.getValue().getLineEnd())};
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
}
