package common;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class GitCommon {
    public static String getParentCommit(Git git, String fixCommit) throws IOException {
        ObjectId lastCommitId = git.getRepository().resolve(fixCommit);

        RevWalk revWalk = new RevWalk(git.getRepository());
        RevCommit commit = revWalk.parseCommit(lastCommitId);

        List<RevCommit> parents = new ArrayList<>();
        for(RevCommit parent : commit.getParents()) {

            RevCommit deepCopy = revWalk.parseCommit(parent.getId());

            parents.add(deepCopy);

        }

        if ( parents.get(0).getTree() != null ) {
            System.out.println(parents.get(0).getName());
        } else {
            System.out.println("first parent tree was null");
        }
        return parents.get(0).getName();
    }
}
