package cz.tmobile.action;

import com.atlassian.crowd.embedded.api.Group;
import com.atlassian.jira.bc.issue.IssueService;
import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.datetime.DateTimeFormatterFactory;
import com.atlassian.jira.exception.CreateException;
import com.atlassian.jira.issue.*;
import com.atlassian.jira.issue.context.IssueContextImpl;
import com.atlassian.jira.issue.customfields.manager.OptionsManager;
import com.atlassian.jira.issue.customfields.option.Option;
import com.atlassian.jira.issue.customfields.view.CustomFieldParamsImpl;
import com.atlassian.jira.issue.fields.CustomField;
import com.atlassian.jira.issue.fields.config.FieldConfig;
import com.atlassian.jira.issue.link.IssueLinkManager;
import com.atlassian.jira.user.ApplicationUser;
import com.atlassian.jira.user.util.UserManager;
import com.atlassian.jira.util.JiraUrlCodec;
import com.atlassian.jira.web.action.issue.IssueCreationHelperBean;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.security.random.DefaultSecureTokenGenerator;
import com.atlassian.security.random.SecureTokenGenerator;
import cz.tmobile.dtos.*;
import cz.tmobile.services.impl.facade.IssueFacade;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import cz.tmobile.Constants;
import cz.tmobile.services.impl.facade.CIHelper;
import cz.tmobile.events.CreateSubtaskEvent;
import com.atlassian.event.api.EventPublisher;
import webwork.action.ActionContext;

import javax.inject.Inject;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

/**
 * Change creation from SEC project
 */







//TO DO  - na produkci zmenit v dto project id projektu SEC a v atlssian-plugin v condition na vuln. issuetype zmenit id issuetype












public class CreateChangeTMCZAction extends com.atlassian.jira.web.action.issue.CreateIssueDetails {

    protected final String PARENT_ISSUE_ID_LINKATTRIB = "parentIssueId";



    private static final Set<String> EMERGENCY_PRIORITIES = new HashSet<>(Arrays.asList(
            Priorities._2_HOUR.getId(),
            Priorities._4_HOUR.getId(),
            Priorities._8_HOUR.getId(),
            Priorities._12_HOUR.getId(),
            Priorities._1_DAYS.getId()));


    private static final Map<Long, Long> OPTION_MAPPING = new HashMap<Long, Long>() {{
        put(Projects.DEM.getId(), Options.TRIGGER_DEMAND.getId());
        put(Projects.CIM.getId(), Options.TRIGGER_INCIDENT.getId());
        put(Projects.IM.getId(), Options.TRIGGER_INCIDENT.getId());
        put(Projects.SEC.getId(), Options.TRIGGER_INCIDENT.getId());
        put(Projects.CFM.getId(), Options.TRIGGER_MAINTANANCE.getId());
        put(Projects.REF.getId(), Options.TRIGGER_REQUEST.getId());
        put(Projects.PBM.getId(), Options.TRIGGER_PROBLEM.getId());
    }};


    private final SecureTokenGenerator secureTokenGenerator;
    private final EventPublisher eventPublisher;



    private String formToken;
    private Long parentIssueId;
    private Issue parentIssue;

    private final IssueManager issueManager;
    private final UserManager userManager;
    private final IssueFacade issueFacade;
    private final OptionsManager optionsManager;
    private final IssueLinkManager issueLinkManager;
    private final CustomFieldManager customFieldManager;

    @Inject
    @Autowired
    public CreateChangeTMCZAction(@NonNull final IssueFacade issueFacade,
            @ComponentImport final IssueFactory issueFactory,
                                  @ComponentImport final IssueCreationHelperBean issueCreationHelperBean,
                                  @ComponentImport final IssueService issueService,
                                  @ComponentImport EventPublisher eventPublisher,
                                  @ComponentImport final TemporaryAttachmentsMonitorLocator temporaryAttachmentsMonitorLocator,
                                  @ComponentImport final IssueLinkManager issueLinkManager,
                                  @ComponentImport final OptionsManager optionsManager,
                                  @ComponentImport final DateTimeFormatterFactory dateTimeFormatterFactory,
                                  @ComponentImport final IssueManager issueManager,
                                  @ComponentImport final CustomFieldManager customFieldManager,
                                  @ComponentImport final UserManager userManager) {
        super(issueFactory, issueCreationHelperBean, issueService, temporaryAttachmentsMonitorLocator);
        this.issueManager = issueManager;
        this.userManager = userManager;
        this.optionsManager = optionsManager;
        this.issueLinkManager = issueLinkManager;
        this.customFieldManager = customFieldManager;
        this.eventPublisher = eventPublisher;
        this.issueFacade = issueFacade;
        secureTokenGenerator = DefaultSecureTokenGenerator.getInstance();
    }

    @Override
    public String doInit() {
        if (isTelecomRequest()) {
            Map parametersMap = new HashMap(ActionContext.getParameters());

            if (Constants.TELECOM_FORM_TOKEN_ACTION_TASK.equals(getActionFromFormToken())) {
                Long parentIssueId = getParentIssueIdFromFormToken();

            }

            if (!parametersMap.containsKey("reporter")) {
                parametersMap.put("reporter", new String[]{getLoggedInUser().getName()});
            }

            ActionContext.setParameters(parametersMap);
        }

        return super.doInit();
    }



    @Override
    public String doDefault() throws Exception {
        Issue parentIssue = getParentIssue();

        setPid(Projects.CHM.getId());
        setIssuetype(ITs.CHANGE.getId());

        fieldValuesHolder.put("reporter", getLoggedInUser().getName());
        if (parentIssue != null) {


            fieldValuesHolder.put("summary", "Issue created from " + parentIssue.getSummary());
            fieldValuesHolder.put(CFs.TRIGGER_ID.getFieldName(), new CustomFieldParamsImpl(customFieldManager.getCustomFieldObject(CFs.TRIGGER_ID.getId()), parentIssue.getKey()));
            fieldValuesHolder.put("description", parentIssue.getDescription());

            CustomField cfAffectedCi = getCustomFieldManager().getCustomFieldObject(CFs.AFFECTED_CI.getId());
            String affectedCi = (String) parentIssue.getCustomFieldValue(cfAffectedCi);
            try {
                fieldValuesHolder.put(CFs.AFFECTED_CIS.getFieldName(), new CustomFieldParamsImpl(customFieldManager.getCustomFieldObject(CFs.AFFECTED_CIS.getId()), CIHelper.xmlToJsonString(affectedCi)));
            } catch (IOException e) {
                log.error(String.format("An error occurred when transforming Affected CI to json string: %s", affectedCi), e);
            }

            Long projectOption = OPTION_MAPPING.get(parentIssue.getProjectId());
            if (projectOption != null) {
                fieldValuesHolder.put(CFs.TRIGGER.getFieldName(), new CustomFieldParamsImpl(customFieldManager.getCustomFieldObject(CFs.TRIGGER.getId()), "" + projectOption));
            }

            boolean emergencyChange = false;
            if (Projects.SEC.getId().equals(parentIssue.getProjectId())) {
                if (EMERGENCY_PRIORITIES.contains(parentIssue.getPriority().getId())) {
                        fieldValuesHolder.put(CFs.CHANGE_URGENCY.getFieldName(), new CustomFieldParamsImpl(customFieldManager.getCustomFieldObject(CFs.CHANGE_URGENCY.getId()), "" + getOption(customFieldManager.getCustomFieldObject(CFs.CHANGE_URGENCY.getId()), "1-Emergency").getOptionId()));
                        emergencyChange = true;
                    }

            }

            log.error("EMERGENCY change: " + emergencyChange);
            //Group Approvers
            if (!emergencyChange) {
                fieldValuesHolder.put(CFs.GROUP_APPROVERS.getFieldName(), new CustomFieldParamsImpl(customFieldManager.getCustomFieldObject(CFs.GROUP_APPROVERS.getId()), "FED_Changemanagement_RG_"));
            }
            /*
            if (!ITs.INCIDENT_NT.getId().equals(parentIssue.getIssueTypeId()) &&
                    !ITs.MASTER_INCIDENT_NTW.getId().equals(parentIssue.getIssueTypeId())) {
                List<Group> realizationTeam = (List<Group>) parentIssue.getCustomFieldValue(customFieldManager.getCustomFieldObject(CFs.REALIZATION_TEAM.getId()));
                if (CollectionUtils.isNotEmpty(realizationTeam)) {
                    fieldValuesHolder.put(CFs.GROUP_APPROVERS.getFieldName(), new CustomFieldParamsImpl(customFieldManager.getCustomFieldObject(CFs.GROUP_APPROVERS.getId()),
                            realizationTeam.stream().map(group -> group.getName()).collect(Collectors.toList())));
                }
            } else {
                if (emergencyChange) {
                    fieldValuesHolder.put(CFs.GROUP_APPROVERS.getFieldName(), new CustomFieldParamsImpl(customFieldManager.getCustomFieldObject(CFs.GROUP_APPROVERS.getId()), "FED_L3_NOC_DISP_TV_RG_"));
                } //else Group Approves will be set by default logic on create transition
            }*/

            if (ITs.ALL_INCIDENTS.getAllIds().contains(parentIssue.getIssueTypeId())) {
                String affectedCI = (String) parentIssue.getCustomFieldValue(customFieldManager.getCustomFieldObject(CFs.AFFECTED_CI.getId()));
            }
        }

        return INPUT;
    }

    @Override
    public String getFormToken() {
        if (formToken == null) {
            formToken = new StringBuilder()
                    .append(Constants.TELECOM_FORM_TOKEN_PREFIX)
                    .append(Constants.TELECOM_FORM_TOKEN_DELIMETER)
                    .append(Constants.TELECOM_FORM_TOKEN_ACTION_CHANGE)
                    .append(Constants.TELECOM_FORM_TOKEN_DELIMETER)
                    .append(parentIssueId)
                    .append(Constants.TELECOM_FORM_TOKEN_DELIMETER)
                    .append(secureTokenGenerator.generateToken())
                    .toString();
        }

        return formToken;
    }

    public Long getParentIssueId() {
        if (parentIssue == null) {
            parentIssue = getIssueManager().getIssueObject(parentIssueId);
        }

        return parentIssue != null ? parentIssue.getId() : null;
    }

    public void setParentIssueId(final Long parentIssueId) {
        this.parentIssueId = parentIssueId;
    }

    public Issue getParentIssue() {
        if (parentIssue == null && parentIssueId != null) {
            parentIssue = getIssueManager().getIssueObject(parentIssueId);
        }

        return parentIssue;
    }


    public Issue getParentIssue(final long issueId) {
        return getParentIssue(issueManager.getIssueObject(issueId));
    }

    public Issue getParentIssue(final Issue issue) {
        if (issue.isSubTask()) {
            return issue.getParentObject();
        } else if(Objects.equals(issue.getIssueTypeId(), ITs.TASK.getId())) {
            Issue parentIssue = issueLinkManager.getInwardLinks(issue.getId())
                    .stream()
                    .map(issueLink -> issueLink.getSourceObject())
                    .findFirst()
                    .orElse(null);
            return parentIssue == null ? issue : parentIssue;
        }

        return issue;
    }


    @Override
    protected String doPostCreationTasks() throws Exception {
        if (isTelecomRequest()) {
            String issueKey = JiraUrlCodec.encode(getKey());
            Long parentIssueId = getParentIssueIdFromFormToken();



            ApplicationUser automation = ComponentAccessor.getUserManager().getUserByName(Constants.USER_AUTOMATION);
            boolean autoCreateExternalEntity = true;

            //dont integrate issue for specific projects
            if (Projects.DT.getId().equals(getIssueObject().getProjectId())) {
                autoCreateExternalEntity = false;
            }

            Issue curIssue = getIssueObject();
            CustomField externalSysCf = customFieldManager.getCustomFieldObject(CFs.EXTERNAL_SYSTEM.getId());
            CustomField changeUrgencyCf = customFieldManager.getCustomFieldObject(CFs.CHANGE_URGENCY.getId());
            CustomField sourceTechnologyCf = customFieldManager.getCustomFieldObject(CFs.SOURCE_TECHNOLOGY.getId());

            log.error("POST CREATion TASK");
            log.error("VALUE: " + curIssue.getCustomFieldValue(changeUrgencyCf).toString());
            log.error("bgooleanL: " + curIssue.getCustomFieldValue(changeUrgencyCf).toString().equals("1-Emergency"));
            if (curIssue.getCustomFieldValue(changeUrgencyCf) != null && curIssue.getCustomFieldValue(changeUrgencyCf).toString().equals("1-Emergency")) {
                log.error("emergency change detected@@@!!!!");
                String sourceTechnologyValue = (String) curIssue.getCustomFieldValue(sourceTechnologyCf);
                if (sourceTechnologyValue != null && sourceTechnologyValue.matches("^IT -")) {
                    issueFacade.setCustomFieldValue(automation, curIssue.getId(), CFs.GROUP_APPROVERS.getId(), "FED_SMC-IT_L1_RG_");
                } else {
                    issueFacade.setCustomFieldValue(automation, curIssue.getId(), CFs.GROUP_APPROVERS.getId(), "FED_L3_NOC_DISP_TV_RG_");

                }
            }

            //dont transition for Internal Task
            String integrationType = (String) curIssue.getCustomFieldValue(customFieldManager.getCustomFieldObject(CFs.INTEGRATION_TYPE.getId()));
            if ("Internal".equals(integrationType)) {
                autoCreateExternalEntity = false;
            }



            Issue parentIssue = getParentIssue(parentIssueId);
            if (Constants.TELECOM_FORM_TOKEN_ACTION_CHANGE.equals(getActionFromFormToken())) {

                createExternalEntityLink(getParentIssue(getIssueManager().getIssueObject(parentIssueId), Constants.CAUSESLINKID).getId(), getIssueObject().getId(), Constants.CAUSESLINKID, automation);


                //copyCommentsAndAttachments(parentIssue, getIssueObject(), automation);
            } else {
                createIssueLinkAsUser(getIssueManager().getIssueObject(parentIssueId), parentIssue, getIssueObject(), automation, autoCreateExternalEntity);
            }
            runEvent();

            if (isIssueValid()) {
                //notificationHelper.publishMWFCreateNotification(parentIssue, modelManager.getAsOptionValue(parentIssue, CFs.ROUTING_METHOD));
                return returnCompleteWithInlineRedirect("/browse/" + issueKey);
            } else {
                errorMessages.clear();
                return returnCompleteWithInlineRedirect("CantBrowseCreatedIssue.jspa?issueKey=" + issueKey);
            }
        } else {
            log.error("NON TELECOM");
            return super.doPostCreationTasks();
        }
    }



    public void createIssueLinkAsUser(final Issue sourceIssue, final Issue parentIssue, final Issue task, final ApplicationUser user, final boolean createExternalEntity) {
            try {
                if (ITs.CONFIGURATION_TASK.getId().equals(task.getIssueTypeId()) && sourceIssue.isSubTask()) {
                    createExternalEntityLink(sourceIssue.getId(), task.getId(), Constants.RELATESLINKID, user);
                } else {
                    createExternalEntityLink(parentIssue.getId(), task.getId(), Constants.RELATESLINKID, user);
                }
            } catch (CreateException e) {
                log.error(String.format("An error occurred when creating issue link between issues %s and %s", parentIssue.getKey(), task.getKey()), e);
            }

    }


    private Issue getParentIssue(final Issue issue, final Long issueLinkType) {
        if (issue.isSubTask()) {
            return issue.getParentObject();
        } else {
            Issue parentIssue = issueLinkManager.getOutwardLinks(issue.getId())
                    .stream()
                    .filter(issueLink -> issueLinkType.equals(issueLink.getLinkTypeId()))
                    .map(issueLink -> issueLink.getSourceObject())
                    .findFirst()
                    .orElse(null);

            return parentIssue == null ? issue : parentIssue;
        }
    }


    private void createExternalEntityLink(final Long parentIssueId, final Long childIssueId, final Long linkTypeId, final ApplicationUser user) throws CreateException {
        if(parentIssueId != null && childIssueId != null){
            issueLinkManager.createIssueLink( parentIssueId, childIssueId, linkTypeId, 0L, user);
        }

    }

    protected boolean isTelecomRequest() {
        return Constants.TELECOM_FORM_TOKEN_PATTERN.matcher(getFormToken()).matches();
    }

    protected Long getParentIssueIdFromFormToken() {
        Matcher matcher = Constants.TELECOM_FORM_TOKEN_PATTERN.matcher(getFormToken());

        if (matcher.matches()) {
            return Long.valueOf(matcher.group(2));
        }

        return null;
    }

    protected String getActionFromFormToken() {
        Matcher matcher = Constants.TELECOM_FORM_TOKEN_PATTERN.matcher(getFormToken());

        if (matcher.matches()) {
            return matcher.group(1);
        }

        return null;
    }

    protected Option getOption(CustomField customField, Object value) {
        FieldConfig fieldConfig = customField.getRelevantConfig(new IssueContextImpl(getPid(), getIssuetype()));
        com.atlassian.jira.issue.customfields.option.Options options = optionsManager.getOptions(fieldConfig);
        return options.stream().filter(o -> value.equals(o.getValue())).findFirst().orElse(null);
    }

    private void runEvent() {
        Issue issue = getIssueObject();
        eventPublisher.publish(new CreateSubtaskEvent(issue));
    }



}
