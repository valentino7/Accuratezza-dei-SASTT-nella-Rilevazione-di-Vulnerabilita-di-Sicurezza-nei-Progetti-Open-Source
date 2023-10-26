package controller;

import entity.VulasEntry;
import IO.ReaderInputs;
import utils.Constants;
import com.opencsv.CSVWriter;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectReader;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;
import org.eclipse.jgit.util.io.DisabledOutputStream;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static IO.ReaderInputs.getAbsolute;
import static common.GitCommon.getParentCommit;

public class CreateMappingParentSonCommit {

    public static void writeMapping(String path, HashMap<String, String> map){
        File file = new File(getAbsolute(path));
        try {
            // create FileWriter object with file as parameter
            FileWriter outputfile = new FileWriter(file);

            // create CSVWriter object filewriter object as parameter
            CSVWriter writer = new CSVWriter(outputfile);

            // adding header to csv
            // CWE ID, Method ID (File$Method$FixCommitID), Badness (Yes/No), Tool ID, Size, CWE Result (predicted), opensource(Y/N)
            // 30, xxx, Yes, SQ, 4000, 40, Yes
            String[] header = { "Project fix commit","Parent Commit" };
            writer.writeNext(header);

            for (Map.Entry<String, String> set : map.entrySet()){
                String[] data = { set.getKey(), set.getValue()};
                writer.writeNext(data);
            }
            // closing writer connection
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void main(String args[]) throws IOException {
        ArrayList<VulasEntry> vulasEntries = ReaderInputs.readVulasCsv(Constants.PATH_VULAS_DB);
        HashMap<String, String> hFixParent = new HashMap<>();

        for (VulasEntry v : vulasEntries) {
            String projectName = v.getProjectUrl().split("/")[v.getProjectUrl().split("/").length - 1];

            String projectPath = "";
            // ATTENZIONE!! vulasEntries Contiene cveid Duplicati

            projectPath = getAbsolute(Constants.PATH_PROJECT_REPOSITORIES) + "\\" +projectName;

            File gitDirectory = new File(projectPath);
            System.out.println(projectPath);
            System.out.println("fixCommit: " + v.getCommitID());

            Git git;
            FileRepositoryBuilder repositoryBuilder = new FileRepositoryBuilder();
            repositoryBuilder.addCeilingDirectory(gitDirectory);
            repositoryBuilder.findGitDir(gitDirectory);

            try {
                git = new Git(repositoryBuilder.build());


                ObjectReader reader = git.getRepository().newObjectReader();
                CanonicalTreeParser oldTreeIter = new CanonicalTreeParser();

                String parentCommit = null;
                parentCommit = getParentCommit(git, v.getCommitID());

                ObjectId oldTree = null;
                oldTree = git.getRepository().resolve(parentCommit + "^{tree}");

                oldTreeIter.reset(reader, oldTree);

                CanonicalTreeParser newTreeIter = new CanonicalTreeParser();
                ObjectId newTree = null;
                newTree = git.getRepository().resolve(v.getCommitID() + "^{tree}");

                //ObjectId newTree = git.getRepository().resolve( "HEAD^{tree}" );
                newTreeIter.reset(reader, newTree);


                DiffFormatter diffFormatter = new DiffFormatter(DisabledOutputStream.INSTANCE);
                diffFormatter.setRepository(git.getRepository());
                List<DiffEntry> entries = diffFormatter.scan(oldTreeIter, newTreeIter);




                hFixParent.put(v.getProjectUrl()+v.getCommitID(), parentCommit);
            }catch (Exception ex) {
                System.err.println("ERRORE:"+ v.getProjectUrl()+","+v.getCommitID());
                ex.printStackTrace();
                continue;
                //throw new RuntimeException(ex);
            }
            writeMapping(Constants.MAPPING_FIX_PARENT_COMMIT, hFixParent);
        }
    }
}
