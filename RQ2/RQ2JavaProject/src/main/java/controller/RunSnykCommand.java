package controller;

import IO.ReaderInputs;
import entity.VulasEntry;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.eclipse.jgit.api.errors.GitAPIException;
import utils.Constants;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import static IO.ReaderInputs.getAbsolute;
import static IO.ReaderInputs.startProcess;

public class RunSnykCommand {


    public static void  runSnykCommand(String path, String name){

        ProcessBuilder processBuilder = new ProcessBuilder(); // pass in your command and options;
        processBuilder.command("powershell", "CD", path,";","powershell","snyk","code", "test", "--json", "|", "out-file", "-encoding", "utf8",  Constants.REPORT_RESULTS+"snyk\\"+name+".json");
        processBuilder.redirectErrorStream(true);

        startProcess(processBuilder);
    }


    public static void main(String args[]) throws IOException, GitAPIException, InterruptedException, ClassNotFoundException, XmlPullParserException {

        ArrayList<VulasEntry> vulasEntries = ReaderInputs.readVulasCsv(Constants.PATH_VULAS_DB);
        HashMap<String, String> fixParent = ReaderInputs.readMappingCommit(Constants.MAPPING_FIX_PARENT_COMMIT);
//////////////////////////////////////////////////////////////////////////////
        int s=0;
        for (VulasEntry e : vulasEntries) {

            String projectName = e.getProjectUrl().split("/")[e.getProjectUrl().split("/").length - 1];

            ArrayList<VulasEntry> lVulas = new ArrayList<>();

            e.setFixCommit(e.getCommitID());
            s += 1;
            // Crea path fix
            // Crea path old commit
            // run command on fix
            // run command on old
            // parsa risultato
            // unisci risultato
            String fixPath = getAbsolute(Constants.PATH_PROJECT_ROOT) + "\\" +projectName + e.getCommitID();
            System.out.println("fix");

            System.out.println(fixPath);

            runSnykCommand(fixPath, projectName + e.getCommitID());


            String parentCommit = fixParent.get(e.getProjectUrl()+e.getFixCommit());
            String oldPath = getAbsolute(Constants.PATH_PROJECT_ROOT) + "\\" +projectName + parentCommit;
            System.out.println("old");
            System.out.println(oldPath);

            runSnykCommand(oldPath, projectName + parentCommit);

        }
        System.out.println(vulasEntries.size());
        System.out.println(s);

    }
}