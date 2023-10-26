package org.jenkinsci.plugins.googleplayandroidpublisher;

import com.google.jenkins.plugins.credentials.oauth.GoogleRobotCredentials;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.model.AbstractProject;
import hudson.model.Describable;
import hudson.model.Item;
import hudson.tasks.BuildStep;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.ComboBoxModel;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import static hudson.Util.fixEmptyAndTrim;
import static hudson.Util.tryParseNumber;
import static hudson.model.Item.EXTENDED_READ;
import static org.jenkinsci.plugins.googleplayandroidpublisher.Constants.DEFAULT_PERCENTAGE;
import static org.jenkinsci.plugins.googleplayandroidpublisher.Constants.PERCENTAGE_FORMATTER;
import static org.jenkinsci.plugins.googleplayandroidpublisher.Constants.ROLLOUT_PERCENTAGES;
import static org.jenkinsci.plugins.googleplayandroidpublisher.ReleaseTrack.getConfigValues;
import static org.jenkinsci.plugins.googleplayandroidpublisher.Util.REGEX_VARIABLE;

public abstract class GooglePlayBuildStepDescriptor<T extends BuildStep & Describable<T>>
        extends BuildStepDescriptor<T> {

    public GooglePlayBuildStepDescriptor() {
        load();
    }

    public ListBoxModel doFillGoogleCredentialsIdItems(@AncestorInPath Item item) {
        // Only allow enumerating credentials if we have the appropriate permission
        if (item == null || !item.hasPermission(EXTENDED_READ)) {
            return new ListBoxModel();
        }

        ListBoxModel credentials = GoogleRobotCredentials.getCredentialsListBox(GooglePlayPublisher.class);
        if (credentials.isEmpty()) {
            credentials.add("(No Google Play account credentials have been added to Jenkins)", null);
        }
        return credentials;
    }

    public FormValidation doCheckGoogleCredentialsId(@AncestorInPath Item item, @QueryParameter String value) {
        // Only allow validating the existence of credentials if we have the appropriate permission
        if (item == null || !item.hasPermission(EXTENDED_READ)) {
            return FormValidation.ok();
        }

        // Complain if no credentials have been set up
        ListBoxModel credentials = GoogleRobotCredentials.getCredentialsListBox(GooglePlayPublisher.class);
        if (credentials.isEmpty()) {
            return FormValidation.error("You must add at least one Google Service Account via the Credentials page");
        }

        // Don't validate value if it hasn't been set, or looks like an expression
        if (value == null || value.isEmpty() || value.matches("\\$\\{[A-Za-z0-9_]+}")) {
            return FormValidation.ok();
        }

        // Otherwise, attempt to load the given credential to see whether it has been set up correctly
        try {
            new CredentialsHandler(value).getServiceAccountCredentials();
        } catch (EphemeralCredentialsException e) {
            // Loading the credential (apparently) goes online, so we may get ephemeral connectivity problems
            return FormValidation.warning(e.getMessage());
        } catch (UploadException e) {
            return FormValidation.error(e.getMessage());
        }

        // Everything is fine
        return FormValidation.ok();
    }

    public FormValidation doCheckApkFilesPattern(@QueryParameter String value) {
        if (fixEmptyAndTrim(value) == null) {
            return FormValidation.error("An APK file path or pattern is required");
        }
        return FormValidation.ok();
    }

    public FormValidation doCheckTrackName(@QueryParameter String value) {
        if (fixEmptyAndTrim(value) == null) {
            return FormValidation.error("A release track is required");
        }
        return FormValidation.ok();
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    public FormValidation doCheckRolloutPercentage(@QueryParameter String value) {
        value = fixEmptyAndTrim(value);
        if (value == null || value.matches(REGEX_VARIABLE)) {
            return FormValidation.ok();
        }

        final double lowest = ROLLOUT_PERCENTAGES[0];
        final double highest = DEFAULT_PERCENTAGE;
        double pct = tryParseNumber(value.replace("%", ""), highest).doubleValue();
        if (Double.compare(pct, lowest) < 0 || Double.compare(pct, DEFAULT_PERCENTAGE) > 0) {
            return FormValidation.error("Percentage value must be between %s and %s%%",
                    PERCENTAGE_FORMATTER.format(lowest), PERCENTAGE_FORMATTER.format(highest));
        }
        return FormValidation.ok();
    }

    public ComboBoxModel doFillTrackNameItems() {
        return new ComboBoxModel(getConfigValues());
    }

    public ComboBoxModel doFillRolloutPercentageItems() {
        ComboBoxModel list = new ComboBoxModel();
        for (double pct : ROLLOUT_PERCENTAGES) {
            list.add(String.format("%s%%", PERCENTAGE_FORMATTER.format(pct)));
        }
        return list;
    }

    public boolean isApplicable(Class<? extends AbstractProject> c) {
        return true;
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
        save();
        return super.configure(req, formData);
    }

}