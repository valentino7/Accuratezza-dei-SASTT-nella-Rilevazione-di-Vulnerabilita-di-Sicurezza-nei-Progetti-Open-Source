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
package org.apache.syncope.core.report;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.transform.sax.TransformerHandler;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.io.IOUtils;
import org.apache.syncope.common.SyncopeConstants;
import org.apache.syncope.common.report.ReportletConf;
import org.apache.syncope.common.types.ReportExecStatus;
import org.apache.syncope.core.persistence.beans.Report;
import org.apache.syncope.core.persistence.beans.ReportExec;
import org.apache.syncope.core.persistence.dao.ReportDAO;
import org.apache.syncope.core.persistence.dao.ReportExecDAO;
import org.apache.syncope.core.rest.data.ReportDataBinder;
import org.apache.syncope.core.util.ApplicationContextProvider;
import org.apache.syncope.core.util.ExceptionUtil;
import org.apache.syncope.core.util.VoidURIResolver;
import org.quartz.DisallowConcurrentExecution;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.xml.sax.helpers.AttributesImpl;

/**
 * Quartz job for executing a given report.
 */
@SuppressWarnings("unchecked")
@DisallowConcurrentExecution
public class ReportJob implements Job {

    /**
     * Logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(ReportJob.class);

    private static final SAXTransformerFactory TRANSFORMER_FACTORY;

    static {
        TRANSFORMER_FACTORY = (SAXTransformerFactory) TransformerFactory.newInstance();
        TRANSFORMER_FACTORY.setURIResolver(new VoidURIResolver());
        try {
            TRANSFORMER_FACTORY.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (TransformerConfigurationException e) {
            LOG.error("Could not enable secure XML processing", e);
        }
    }

    /**
     * Report DAO.
     */
    @Autowired
    private ReportDAO reportDAO;

    /**
     * Report execution DAO.
     */
    @Autowired
    private ReportExecDAO reportExecDAO;

    /**
     * Report data binder.
     */
    @Autowired
    private ReportDataBinder dataBinder;

    /**
     * Id, set by the caller, for identifying the report to be executed.
     */
    private Long reportId;

    /**
     * Report id setter.
     *
     * @param reportId to be set
     */
    public void setReportId(final Long reportId) {
        this.reportId = reportId;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public void execute(final JobExecutionContext context) throws JobExecutionException {
        Report report = reportDAO.find(reportId);
        if (report == null) {
            throw new JobExecutionException("Report " + reportId + " not found");
        }

        // 1. create execution
        ReportExec execution = new ReportExec();
        execution.setStatus(ReportExecStatus.STARTED);
        execution.setStartDate(new Date());
        execution.setReport(report);
        execution = reportExecDAO.save(execution);

        report.addExec(execution);
        report = reportDAO.save(report);

        // 2. define a SAX handler for generating result as XML
        TransformerHandler handler;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        zos.setLevel(Deflater.BEST_COMPRESSION);
        try {
            handler = TRANSFORMER_FACTORY.newTransformerHandler();
            Transformer serializer = handler.getTransformer();
            serializer.setOutputProperty(OutputKeys.ENCODING, SyncopeConstants.DEFAULT_ENCODING);
            serializer.setOutputProperty(OutputKeys.INDENT, "yes");

            // a single ZipEntry in the ZipOutputStream
            zos.putNextEntry(new ZipEntry(report.getName()));

            // streaming SAX handler in a compressed byte array stream
            handler.setResult(new StreamResult(zos));
        } catch (Exception e) {
            throw new JobExecutionException("While configuring for SAX generation", e, true);
        }

        execution.setStatus(ReportExecStatus.RUNNING);
        execution = reportExecDAO.save(execution);

        // 3. actual report execution
        StringBuilder reportExecutionMessage = new StringBuilder();
        try {
            // report header
            handler.startDocument();
            AttributesImpl atts = new AttributesImpl();
            atts.addAttribute("", "", ReportXMLConst.ATTR_NAME, ReportXMLConst.XSD_STRING, report.getName());
            handler.startElement("", "", ReportXMLConst.ELEMENT_REPORT, atts);

            // iterate over reportlet instances defined for this report
            for (ReportletConf reportletConf : report.getReportletConfs()) {
                Class<Reportlet> reportletClass =
                        dataBinder.findReportletClassHavingConfClass(reportletConf.getClass());
                if (reportletClass != null) {
                    Reportlet<ReportletConf> autowired =
                            (Reportlet<ReportletConf>) ApplicationContextProvider.getBeanFactory().
                                    createBean(reportletClass, AbstractBeanDefinition.AUTOWIRE_BY_TYPE, false);
                    autowired.setConf(reportletConf);

                    // invoke reportlet
                    try {
                        autowired.extract(handler);
                    } catch (Exception e) {
                        execution.setStatus(ReportExecStatus.FAILURE);

                        Throwable t = e instanceof ReportException
                                ? e.getCause()
                                : e;
                        reportExecutionMessage.
                                append(ExceptionUtil.getFullStackTrace(t)).
                                append("\n==================\n");
                    }
                }
            }

            // report footer
            handler.endElement("", "", ReportXMLConst.ELEMENT_REPORT);
            handler.endDocument();

            if (!ReportExecStatus.FAILURE.name().equals(execution.getStatus())) {
                execution.setStatus(ReportExecStatus.SUCCESS);
            }
        } catch (Exception e) {
            execution.setStatus(ReportExecStatus.FAILURE);
            reportExecutionMessage.append(ExceptionUtil.getFullStackTrace(e));

            throw new JobExecutionException(e, true);
        } finally {
            try {
                zos.closeEntry();
                IOUtils.closeQuietly(zos);
                IOUtils.closeQuietly(baos);
            } catch (IOException e) {
                LOG.error("While closing StreamResult's backend", e);
            }

            execution.setExecResult(baos.toByteArray());
            execution.setMessage(reportExecutionMessage.toString());
            execution.setEndDate(new Date());
            reportExecDAO.save(execution);
        }
    }
}
