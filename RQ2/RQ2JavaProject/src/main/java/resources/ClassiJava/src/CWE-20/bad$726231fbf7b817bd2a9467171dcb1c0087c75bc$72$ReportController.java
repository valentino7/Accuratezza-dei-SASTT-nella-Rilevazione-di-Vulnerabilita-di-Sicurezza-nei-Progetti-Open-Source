/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.core.rest.controller;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipInputStream;
import org.apache.cocoon.optional.pipeline.components.sax.fop.FopSerializer;
import org.apache.cocoon.pipeline.NonCachingPipeline;
import org.apache.cocoon.pipeline.Pipeline;
import org.apache.cocoon.sax.SAXPipelineComponent;
import org.apache.cocoon.sax.component.XMLGenerator;
import org.apache.cocoon.sax.component.XMLSerializer;
import org.apache.cocoon.sax.component.XSLTTransformer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.syncope.common.report.ReportletConf;
import org.apache.syncope.common.to.ReportExecTO;
import org.apache.syncope.common.to.ReportTO;
import org.apache.syncope.common.types.ReportExecExportFormat;
import org.apache.syncope.common.types.ReportExecStatus;
import org.apache.syncope.common.types.ClientExceptionType;
import org.apache.syncope.common.SyncopeClientException;
import org.apache.syncope.common.reqres.BulkActionResult;
import org.apache.syncope.common.to.AbstractExecTO;
import org.apache.syncope.common.types.JobAction;
import org.apache.syncope.common.types.JobStatusType;
import org.apache.syncope.core.init.JobInstanceLoader;
import org.apache.syncope.core.persistence.beans.Report;
import org.apache.syncope.core.persistence.beans.ReportExec;
import org.apache.syncope.core.persistence.dao.NotFoundException;
import org.apache.syncope.core.persistence.dao.ReportDAO;
import org.apache.syncope.core.persistence.dao.ReportExecDAO;
import org.apache.syncope.core.persistence.dao.search.OrderByClause;
import org.apache.syncope.core.report.Reportlet;
import org.apache.syncope.core.report.cocoon.TextSerializer;
import org.apache.syncope.core.rest.data.ReportDataBinder;
import org.apache.xmlgraphics.util.MimeConstants;
import org.quartz.JobKey;
import org.quartz.Scheduler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class ReportController extends AbstractJobController<ReportTO> {

    @Autowired
    private ReportDAO reportDAO;

    @Autowired
    private ReportExecDAO reportExecDAO;

    @Autowired
    private JobInstanceLoader jobInstanceLoader;

    @Autowired
    private ReportDataBinder binder;

    @PreAuthorize("hasRole('REPORT_CREATE')")
    public ReportTO create(final ReportTO reportTO) {
        Report report = new Report();
        binder.getReport(report, reportTO);
        report = reportDAO.save(report);

        try {
            jobInstanceLoader.registerJob(report);
        } catch (Exception e) {
            LOG.error("While registering quartz job for report " + report.getId(), e);

            SyncopeClientException sce = SyncopeClientException.build(ClientExceptionType.Scheduling);
            sce.getElements().add(e.getMessage());
            throw sce;
        }

        return binder.getReportTO(report);
    }

    @PreAuthorize("hasRole('REPORT_UPDATE')")
    public ReportTO update(final ReportTO reportTO) {
        Report report = reportDAO.find(reportTO.getId());
        if (report == null) {
            throw new NotFoundException("Report " + reportTO.getId());
        }

        binder.getReport(report, reportTO);
        report = reportDAO.save(report);

        try {
            jobInstanceLoader.registerJob(report);
        } catch (Exception e) {
            LOG.error("While registering quartz job for report " + report.getId(), e);

            SyncopeClientException sce = SyncopeClientException.build(ClientExceptionType.Scheduling);
            sce.getElements().add(e.getMessage());
            throw sce;
        }

        return binder.getReportTO(report);
    }

    @PreAuthorize("hasRole('REPORT_LIST')")
    public int count() {
        return reportDAO.count();
    }

    @PreAuthorize("hasRole('REPORT_LIST')")
    public List<ReportTO> list(final int page, final int size, final List<OrderByClause> orderByClauses) {
        List<Report> reports = reportDAO.findAll(page, size, orderByClauses);
        List<ReportTO> result = new ArrayList<ReportTO>(reports.size());
        for (Report report : reports) {
            result.add(binder.getReportTO(report));
        }
        return result;
    }

    @PreAuthorize("hasRole('REPORT_LIST')")
    @SuppressWarnings("rawtypes")
    public Set<String> getReportletConfClasses() {
        Set<String> reportletConfClasses = new HashSet<String>();

        for (Class<Reportlet> reportletClass : binder.getAllReportletClasses()) {
            Class<? extends ReportletConf> reportletConfClass = binder.getReportletConfClass(reportletClass);
            if (reportletConfClass != null) {
                reportletConfClasses.add(reportletConfClass.getName());
            }
        }

        return reportletConfClasses;
    }

    @PreAuthorize("hasRole('REPORT_READ')")
    public ReportTO read(final Long reportId) {
        Report report = reportDAO.find(reportId);
        if (report == null) {
            throw new NotFoundException("Report " + reportId);
        }
        return binder.getReportTO(report);
    }

    @PreAuthorize("hasRole('REPORT_READ')")
    @Transactional(readOnly = true)
    public ReportExecTO readExecution(final Long executionId) {
        ReportExec reportExec = reportExecDAO.find(executionId);
        if (reportExec == null) {
            throw new NotFoundException("Report execution " + executionId);
        }
        return binder.getReportExecTO(reportExec);
    }

    @PreAuthorize("hasRole('REPORT_READ')")
    public void exportExecutionResult(final OutputStream os, final ReportExec reportExec,
            final ReportExecExportFormat format) {

        // streaming SAX handler from a compressed byte array stream
        ByteArrayInputStream bais = new ByteArrayInputStream(reportExec.getExecResult());
        ZipInputStream zis = new ZipInputStream(bais);
        try {
            // a single ZipEntry in the ZipInputStream (see ReportJob)
            zis.getNextEntry();

            Pipeline<SAXPipelineComponent> pipeline = new NonCachingPipeline<SAXPipelineComponent>();
            pipeline.addComponent(new XMLGenerator(zis));

            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("status", reportExec.getStatus());
            parameters.put("message", reportExec.getMessage());
            parameters.put("startDate", reportExec.getStartDate());
            parameters.put("endDate", reportExec.getEndDate());

            switch (format) {
                case HTML:
                    XSLTTransformer xsl2html = new XSLTTransformer(getClass().getResource("/report/report2html.xsl"));
                    xsl2html.setParameters(parameters);
                    pipeline.addComponent(xsl2html);
                    pipeline.addComponent(XMLSerializer.createXHTMLSerializer());
                    break;

                case PDF:
                    XSLTTransformer xsl2pdf = new XSLTTransformer(getClass().getResource("/report/report2fo.xsl"));
                    xsl2pdf.setParameters(parameters);
                    pipeline.addComponent(xsl2pdf);
                    pipeline.addComponent(new FopSerializer(MimeConstants.MIME_PDF));
                    break;

                case RTF:
                    XSLTTransformer xsl2rtf = new XSLTTransformer(getClass().getResource("/report/report2fo.xsl"));
                    xsl2rtf.setParameters(parameters);
                    pipeline.addComponent(xsl2rtf);
                    pipeline.addComponent(new FopSerializer(MimeConstants.MIME_RTF));
                    break;

                case CSV:
                    XSLTTransformer xsl2csv = new XSLTTransformer(getClass().getResource("/report/report2csv.xsl"));
                    xsl2csv.setParameters(parameters);
                    pipeline.addComponent(xsl2csv);
                    pipeline.addComponent(new TextSerializer());
                    break;

                case XML:
                default:
                    pipeline.addComponent(XMLSerializer.createXMLSerializer());
            }

            pipeline.setup(os);
            pipeline.execute();

            LOG.debug("Result of {} successfully exported as {}", reportExec, format);
        } catch (Exception e) {
            LOG.error("While exporting content", e);
        } finally {
            IOUtils.closeQuietly(zis);
            IOUtils.closeQuietly(bais);
        }
    }

    @PreAuthorize("hasRole('REPORT_READ')")
    public ReportExec getAndCheckReportExec(final Long executionId) {
        ReportExec reportExec = reportExecDAO.find(executionId);
        if (reportExec == null) {
            throw new NotFoundException("Report execution " + executionId);
        }
        if (!ReportExecStatus.SUCCESS.name().equals(reportExec.getStatus()) || reportExec.getExecResult() == null) {
            SyncopeClientException sce = SyncopeClientException.build(ClientExceptionType.InvalidReportExec);
            sce.getElements().add(reportExec.getExecResult() == null
                    ? "No report data produced"
                    : "Report did not run successfully");
            throw sce;
        }
        return reportExec;
    }

    @PreAuthorize("hasRole('REPORT_EXECUTE')")
    public ReportExecTO execute(final Long reportId) {
        Report report = reportDAO.find(reportId);
        if (report == null) {
            throw new NotFoundException("Report " + reportId);
        }

        try {
            jobInstanceLoader.registerJob(report);

            scheduler.getScheduler().triggerJob(
                    new JobKey(JobInstanceLoader.getJobName(report), Scheduler.DEFAULT_GROUP));
        } catch (Exception e) {
            LOG.error("While executing report {}", report, e);

            SyncopeClientException sce = SyncopeClientException.build(ClientExceptionType.Scheduling);
            sce.getElements().add(e.getMessage());
            throw sce;
        }

        ReportExecTO result = new ReportExecTO();
        result.setReport(reportId);
        result.setStartDate(new Date());
        result.setStatus(ReportExecStatus.STARTED.name());
        result.setMessage("Job fired; waiting for results...");

        return result;
    }

    @PreAuthorize("hasRole('REPORT_DELETE')")
    public ReportTO delete(final Long reportId) {
        Report report = reportDAO.find(reportId);
        if (report == null) {
            throw new NotFoundException("Report " + reportId);
        }

        ReportTO deletedReport = binder.getReportTO(report);
        jobInstanceLoader.unregisterJob(report);
        reportDAO.delete(report);
        return deletedReport;
    }

    @PreAuthorize("hasRole('REPORT_DELETE')")
    public ReportExecTO deleteExecution(final Long executionId) {
        ReportExec reportExec = reportExecDAO.find(executionId);
        if (reportExec == null) {
            throw new NotFoundException("Report execution " + executionId);
        }

        ReportExecTO reportExecToDelete = binder.getReportExecTO(reportExec);
        reportExecDAO.delete(reportExec);
        return reportExecToDelete;
    }

    @PreAuthorize("hasRole('REPORT_DELETE')")
    public BulkActionResult deleteExecutions(
            final Long reportId,
            final Date startedBefore, final Date startedAfter, final Date endedBefore, final Date endedAfter) {

        Report report = reportDAO.find(reportId);
        if (report == null) {
            throw new NotFoundException("Report " + reportId);
        }

        BulkActionResult res = new BulkActionResult();

        for (ReportExec exec : reportExecDAO.findAll(report, startedBefore, startedAfter, endedBefore, endedAfter)) {
            try {
                reportExecDAO.delete(exec);
                res.add(exec.getId(), BulkActionResult.Status.SUCCESS);
            } catch (Exception e) {
                LOG.error("Error deleting execution {} of report {}", exec.getId(), reportId, e);
                res.add(exec.getId(), BulkActionResult.Status.FAILURE);
            }
        }

        return res;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected ReportTO resolveReference(final Method method, final Object... args)
            throws UnresolvedReferenceException {

        Long id = null;

        if (ArrayUtils.isNotEmpty(args) && ("create".equals(method.getName())
                || "update".equals(method.getName())
                || "delete".equals(method.getName()))) {
            for (int i = 0; id == null && i < args.length; i++) {
                if (args[i] instanceof Long) {
                    id = (Long) args[i];
                } else if (args[i] instanceof ReportTO) {
                    id = ((ReportTO) args[i]).getId();
                }
            }
        }

        if ((id != null) && !id.equals(0l)) {
            try {
                return binder.getReportTO(reportDAO.find(id));
            } catch (Throwable ignore) {
                LOG.debug("Unresolved reference", ignore);
                throw new UnresolvedReferenceException(ignore);
            }
        }

        throw new UnresolvedReferenceException();
    }

    @Override
    @PreAuthorize("hasRole('REPORT_LIST')")
    public <E extends AbstractExecTO> List<E> listJobs(final JobStatusType type, Class<E> reference) {
        return super.listJobs(type, reference);
    }

    @PreAuthorize("hasRole('REPORT_EXECUTE')")
    public void actionJob(final Long reportId, final JobAction action) {
        Report report = reportDAO.find(reportId);
        if (report == null) {
            throw new NotFoundException("Report " + reportId);
        }
        String jobName = JobInstanceLoader.getJobName(report);
        actionJob(jobName, action);
    }

    @Override
    protected Long getIdFromJobName(JobKey jobKey) {
        return JobInstanceLoader.getReportIdFromJobName(jobKey.getName());
    }
}
