#!/usr/bin/env node

import * as _ from '@snyk/lodash';
import chalk from 'chalk';
import * as debugModule from 'debug';
import fs = require('fs');
import Handlebars = require('handlebars');
import marked = require('marked');
import moment = require('moment');
import path = require('path');
import { addIssueDataToPatch, getUpgrades, severityMap, IacProjectType } from './vuln';
import {
  processSourceCode,
} from './codeutil';

const debug = debugModule('snyk-to-html');

const defaultRemediationText = '## Remediation\nThere is no remediation at the moment';

function readFile(filePath: string, encoding: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    fs.readFile(filePath, encoding, (err, data) => {
      if (err) {
        reject(err);
      }
      resolve(data);
    });
  });
}

function handleInvalidJson(reason: any) {
  if (reason.isInvalidJson) {
    reason.message = reason.message + 'Error running `snyk-to-html`. Please check you are providing the correct parameters. ' +
      'Is the issue persists contact support@snyk.io';
  }
  console.log(reason.message);
}

function promisedParseJSON(json) {
  return new Promise((resolve, reject) => {
    try {
      resolve(JSON.parse(json));
    } catch (error) {
      error.message = chalk.red.bold('The source provided is not a valid json! Please validate that the input provided to the CLI is an actual JSON\n\n' +
        'Tip: To find more information, try running `snyk-to-html` in debug mode by appending to the CLI the `-d` parameter\n\n');
      debug(`Input provided to the CLI: \n${json}\n\n`);
      error.isInvalidJson = true;
      reject(error);
    }
  });
}

class SnykToHtml {
  public static run(dataSource: string,
    remediation: boolean,
    hbsTemplate: string,
    summary: boolean,
    reportCallback: (value: string) => void): void {
    SnykToHtml
      .runAsync(dataSource, remediation, hbsTemplate, summary)
      .then(reportCallback)
      .catch(handleInvalidJson);
  }

  public static async runAsync(source: string,
    remediation: boolean,
    template: string,
    summary: boolean): Promise<string> {
    const promisedString = source ? readFile(source, 'utf8') : readInputFromStdin();
    return promisedString
      .then(promisedParseJSON).then((data: any) => {
        if (
          data?.infrastructureAsCodeIssues ||
          data[0]?.infrastructureAsCodeIssues
        ) {
          // for IaC input we need to change the default template to an IaC specific template
          // at the same time we also want to support the -t / --template flag
          template =
            template === path.join(__dirname, '../../template/test-report.hbs')
              ? path.join(__dirname, '../../template/iac/test-report.hbs')
              : template;
          return processIacData(data, template, summary);
        } else if (data?.runs && data?.runs[0].tool.driver.name === 'SnykCode') {
          template =
            template === path.join(__dirname, '../../template/test-report.hbs')
              ? path.join(__dirname, '../../template/code/test-report.hbs')
              : template;
          return processCodeData(data, template, summary);
        } else {
          return processData(data, remediation, template, summary);
        }
      });
  }
}

export { SnykToHtml };

function metadataForVuln(vuln: any) {
  let { cveSpaced, cveLineBreaks } = concatenateCVEs(vuln)

  return {
    id: vuln.id,
    title: vuln.title,
    name: vuln.name,
    info: vuln.info || 'No information available.',
    severity: vuln.severity,
    severityValue: severityMap[vuln.severity],
    description: vuln.description || 'No description available.',
    fixedIn: vuln.fixedIn,
    packageManager: vuln.packageManager,
    version: vuln.version,
    cvssScore: vuln.cvssScore,
    cveSpaced: cveSpaced || 'No CVE found.',
    cveLineBreaks: cveLineBreaks || 'No CVE found.',
    disclosureTime: dateFromDateTimeString(vuln.disclosureTime || ''),
    publicationTime: dateFromDateTimeString(vuln.publicationTime || ''),
    license: vuln.license || undefined
  };
}

function concatenateCVEs(vuln: any) {
  let cveSpaced = ''
  let cveLineBreaks = ''

  if (vuln.identifiers) {
    vuln.identifiers.CVE.forEach(function (c) {
      let cveLink = `<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${c}">${c}</a>`
      cveSpaced += `${cveLink}&nbsp;`
      cveLineBreaks += `${cveLink}</br>`
    })
  }

  return { cveSpaced, cveLineBreaks }
}

function dateFromDateTimeString(dateTimeString: string) {
  return dateTimeString.substr(0, 10);
}

function groupVulns(vulns) {
  const result = {};
  let uniqueCount = 0;
  let pathsCount = 0;

  if (vulns && Array.isArray(vulns)) {
    vulns.map(vuln => {
      if (!result[vuln.id]) {
        result[vuln.id] = { list: [vuln], metadata: metadataForVuln(vuln) };
        pathsCount++;
        uniqueCount++;
      } else {
        result[vuln.id].list.push(vuln);
        pathsCount++;
      }
    });
  }

  return {
    vulnerabilities: result,
    vulnerabilitiesUniqueCount: uniqueCount,
    vulnerabilitiesPathsCount: pathsCount,
  };
}

async function compileTemplate(fileName: string): Promise<HandlebarsTemplateDelegate> {
  return readFile(fileName, 'utf8').then(Handlebars.compile);
}

async function registerPeerPartial(templatePath: string, name: string): Promise<void> {
  const dir = path.dirname(templatePath);
  const file = path.join(dir, `test-report.${name}.hbs`);
  const template = await compileTemplate(file);
  Handlebars.registerPartial(name, template);
}

async function generateTemplate(data: any,
  template: string,
  showRemediation: boolean,
  summary: boolean):
  Promise<string> {
  if (showRemediation && data.remediation) {
    data.showRemediations = showRemediation;
    const { upgrade, pin, unresolved, patch } = data.remediation;
    data.anyRemediations = !_.isEmpty(upgrade) ||
      !_.isEmpty(patch) || !_.isEmpty(pin);
    data.anyUnresolved = !!unresolved?.vulnerabilities;
    data.unresolved = groupVulns(unresolved);
    data.upgrades = getUpgrades(upgrade, data.vulnerabilities);
    data.pins = getUpgrades(pin, data.vulnerabilities);
    data.patches = addIssueDataToPatch(
      patch,
      data.vulnerabilities,
    );
  }
  const vulnMetadata = groupVulns(data.vulnerabilities);
  const sortedVulns = _.orderBy(
    vulnMetadata.vulnerabilities,
    ['metadata.severityValue', 'metadata.name'],
    ['desc', 'desc'],
  );
  data.hasMetatableData = !!data.projectName || !!data.path || !!data.displayTargetFile;
  data.vulnerabilities = sortedVulns;
  data.uniqueCount = vulnMetadata.vulnerabilitiesUniqueCount;
  data.summary = vulnMetadata.vulnerabilitiesPathsCount + ' vulnerable dependency paths';
  data.showSummaryOnly = summary;

  await registerPeerPartial(template, 'inline-css');
  await registerPeerPartial(template, 'header');
  await registerPeerPartial(template, 'metatable-css');
  await registerPeerPartial(template, 'metatable');
  await registerPeerPartial(template, 'inline-js');
  await registerPeerPartial(template, 'vuln-card');
  await registerPeerPartial(template, 'remediation-css');
  await registerPeerPartial(template, 'actionable-remediations');

  //console.log('sortedVulns: ' + JSON.stringify(sortedVulns))
  var gitLabVulns: any[] = [];
  sortedVulns.forEach(vuln => {

    var identifiers: any[] = [];
    vuln.list.forEach(l => {
      var lType = l.type;
      if (lType == undefined || lType == "") {
        lType = "Unknown";
      }
      var identifier = {
        "type": lType,
        "name": l.name,
        "value": l.id,
      }
      identifiers.push(identifier);
    })

    //console.log('vuln: ' + JSON.stringify(vuln))
    const capitalizeseverity = vuln.metadata.severity[0].toUpperCase() + vuln.metadata.severity.slice(1);
    var gitLabVuln = {
      "id": vuln.metadata.id,
      "category": "dependency_scanning",
      "name": vuln.metadata.title,
      "message": vuln.metadata.name,
      "description": vuln.metadata.description,
      "severity": capitalizeseverity,
      "solution": "Upgrade to latest versions.",
      "cve": vuln.metadata.cveSpaced,
      "identifiers": [
        {
          "type": "cve",
          "name": vuln.metadata.cveSpaced,
          "value": vuln.metadata.cveSpaced,
        }
      ],
      "location": {
        "file": vuln.metadata.name,
        "dependency": {
          "package": {
            "name": vuln.metadata.name,
          },
          "version": vuln.metadata.version
        }
      },
      "scanner": {
        "id": "snyk",
        "name": "Snyk"
      }
    }

    gitLabVulns.push(gitLabVuln)
  });

  /*var dep_files = [
    {
      "path": "Unknown",
      "package_manager": "npm",
      "dependencies": [
        {
          "package": {
            "name": "test"
          },
          "version": "0.4.7",
          "iid": 1234,
          "direct": true,
          "dependency_path": [
            {
              "iid": 1234
            }
          ]
        }
      ]
    }
  ]

  var jsonOutput = {
    "version": "14.1.2",
    "vulnerabilities": gitLabVulns,
    "dependency_files": dep_files
  }*/
  var jsonOutput = {
    "version": "14.1.2",
    "vulnerabilities": gitLabVulns,
    "dependency_files": data.uniqueLibs
  }

  return JSON.stringify(jsonOutput);
}

async function generateIacTemplate(
  data: any,
  template: string,
): Promise<string> {
  await registerPeerPartial(template, 'inline-css');
  await registerPeerPartial(template, 'header');
  await registerPeerPartial(template, 'metatable-css');
  await registerPeerPartial(template, 'metatable');
  await registerPeerPartial(template, 'inline-js');
  await registerPeerPartial(template, 'vuln-card');

  const htmlTemplate = await compileTemplate(template);

  return htmlTemplate(data);
}

async function generateCodeTemplate(
  data: any,
  template: string,
): Promise<string> {
  await registerPeerPartial(template, 'inline-css');
  await registerPeerPartial(template, 'inline-js');
  await registerPeerPartial(template, 'header');
  await registerPeerPartial(template, 'metatable-css');
  await registerPeerPartial(template, 'metatable');
  await registerPeerPartial(template, 'code-snip');

  const htmlTemplate = await compileTemplate(template);

  return htmlTemplate(data);
}

function mergeData(dataArray: any[]): any {
  const vulnsArrays = dataArray.map(project => project.vulnerabilities || []);
  const aggregateVulnerabilities = [].concat(...vulnsArrays);

  var totalUniqueLibs: string[] = [];
  //console.log(JSON.stringify(dataArray));
  dataArray.forEach(vulns => {
    vulns.vulnerabilities.forEach(vuln => {
      console.log(vuln.packageName);
      if (!totalUniqueLibs.includes(vuln.packageName)) {
        totalUniqueLibs.push(vuln.packageName)
      }
    })
  });
  const totalUniqueCount =
    dataArray.reduce((acc, item) => acc + item.vulnerabilities.length || 0, 0);
  const totalDepCount =
    dataArray.reduce((acc, item) => acc + item.dependencyCount || 0, 0);

  const paths = dataArray.map(project => ({ path: project.path, packageManager: project.packageManager }));

  return {
    vulnerabilities: aggregateVulnerabilities,
    uniqueCount: totalUniqueCount,
    summary: aggregateVulnerabilities.length + ' vulnerable dependency paths',
    dependencyCount: totalDepCount,
    paths,
    totalUniqueLibsCount: totalUniqueLibs.length,
  };
}

async function processData(data: any, remediation: boolean, template: string, summary: boolean): Promise<string> {
  if (!Array.isArray(data)) {
    var uniqueLibs: any[] = [];
    var totalUniqueLibs: string[] = [];
    var totalLicensesIssues: number = 0;
    var totalUniqueLicenses: string[] = [];
    var licenseDistribution = new Map();
    licenseDistribution.set('License', 'Count')
    var severityCritical: number = 0;
    var severityHigh: number = 0;
    var severityMedium: number = 0;
    var severityLow: number = 0;
    //console.log(JSON.stringify(data));
    //var json = JSON.parse(data)
    data.vulnerabilities.forEach(vuln => {
      if (!totalUniqueLibs.includes(vuln.packageName)) {
        totalUniqueLibs.push(vuln.packageName)

        /*var lib = {
          "path": vuln.name,
          "package_manager": vuln.packageManager,
          "dependencies": [{
            "version": vuln.version
          }]
        }*/
        var lib = {
          "path": JSON.stringify(vuln.from),
          "package_manager": vuln.packageManager,
          "dependencies": [
            {
              "package": {
                "name": vuln.name,
              },
              "version": vuln.version,
              "iid": 1234,
              "direct": true,
              "dependency_path": [
                {
                  "iid": 1234
                }
              ]
            }
          ]
        }
        uniqueLibs.push(lib);
      }

      if (vuln.type === "license") {
        totalLicensesIssues++;
        if (!totalUniqueLicenses.includes(vuln.license)) {
          //console.log('here');
          totalUniqueLicenses.push(vuln.license)
          licenseDistribution.set(vuln.license, 1)
        }
        else {
          var licCount = licenseDistribution.get(vuln.license);
          licCount = licCount + 1;
          //console.log('licCount: ' + licCount);
          licenseDistribution.set(vuln.license, licCount);
        }
      }

      if (vuln.severity === 'critical') {
        severityCritical++;
      }
      if (vuln.severity === 'high') {
        severityHigh++;
      }
      if (vuln.severity === 'medium') {
        severityMedium++;
      }
      if (vuln.severity === 'low') {
        severityLow++;
      }
    });
    console.log('total lic issues: ' + totalLicensesIssues);
    console.log('unique licenses: ' + totalUniqueLicenses.length);
    /*console.log(JSON.stringify(data.licensesPolicy.orgLicenseRules['GPL-2.0']))
    data.licensesPolicy.forEach(lic => {
      if (!totalLicenseIssues.includes(lic.packageName)) {
        //totalLicenseIssues.push(lic.packageName)
      }
    });*/
    data.uniqueLibs = uniqueLibs;
    data.totalUniqueLibsCount = totalUniqueLibs.length;
    data.vulnerabilityRiskLabel = "Low";
    data.vulnerabilityRisk = "data:image/png;base64,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";
    if (severityMedium > 0) {
      data.vulnerabilityRiskLabel = "Medium";
      data.vulnerabilityRisk = "https://upload.wikimedia.org/wikipedia/commons/thumb/9/99/OOjs_UI_icon_alert-yellow.svg/240px-OOjs_UI_icon_alert-yellow.svg.png";
    }
    if (severityHigh > 0) {
      data.vulnerabilityRiskLabel = "High";
      data.vulnerabilityRisk = "https://cdn1.iconfinder.com/data/icons/color-bold-style/21/08-512.png";
    }
    if (severityCritical > 0) {
      data.vulnerabilityRiskLabel = "Critical";
      data.vulnerabilityRisk = "https://cdn0.iconfinder.com/data/icons/simple-heptagonal-1/64/Simple_Heptagonal_Set_1-15-512.png";
    }
    data.severityCritical = severityCritical;
    data.severityHigh = severityHigh;
    data.severityMedium = severityMedium;
    data.severityLow = severityLow;
    data.totalLicensesIssues = totalLicensesIssues;
    data.totalUniqueLicenses = totalUniqueLicenses;
    data.totalUniqueLicensesCount = totalUniqueLicenses.length;

    var licDistro = '[';
    var i = 0;
    licenseDistribution.forEach((value, key, map) => {
      if (i == 0) {
        licDistro += `["` + key + `","` + value + `"],`;
      }
      else {
        licDistro += `["` + key + `",` + value + `],`;
      }
      i++
    });
    licDistro += ']';
    data.licenseDistribution = licDistro;

    //console.log(licDistro)
  }
  const mergedData = Array.isArray(data) ? mergeData(data) : data;
  return generateTemplate(mergedData, template, remediation, summary);
}

async function processIacData(data: any, template: string, summary: boolean): Promise<string> {
  if (data.error) {
    return generateIacTemplate(data, template);
  }

  const dataArray = Array.isArray(data) ? data : [data];
  dataArray.forEach(project => {
    project.infrastructureAsCodeIssues.forEach(issue => {
      issue.severityValue = severityMap[issue.severity];
    });
  });
  const projectsArrays = dataArray.map((project) => {
    return {
      targetFile: project.targetFile,
      targetFilePath: project.targetFilePath,
      projectType: IacProjectType[project.projectType],
      infrastructureAsCodeIssues: _.orderBy(
        project.infrastructureAsCodeIssues,
        ['severityValue', 'title'],
        ['desc', 'asc'],
      ),
    };
  });
  const totalIssues = projectsArrays.reduce((acc, item) => acc + item.infrastructureAsCodeIssues.length || 0, 0);

  const processedData = {
    projects: projectsArrays,
    showSummaryOnly: summary,
    totalIssues,
  }

  return generateIacTemplate(processedData, template);
}

async function processCodeData(
  data: any,
  template: string,
  summary: boolean,
): Promise<string> {
  if (data.error) {
    return generateCodeTemplate(data, template);
  }
  const dataArray = Array.isArray(data) ? data : [data];

  const OrderedIssuesArray = await processSourceCode(dataArray);

  const totalIssues = dataArray[0].runs[0].results.length;
  const processedData = {
    projects: OrderedIssuesArray,
    showSummaryOnly: summary,
    totalIssues,
  };
  return generateCodeTemplate(processedData, template);
}

async function readInputFromStdin(): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let jsonString = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('readable', () => {
      const chunk = process.stdin.read();
      if (chunk !== null) {
        jsonString += chunk;
      }
    });
    process.stdin.on('error', reject);
    process.stdin.on('end', () => resolve(jsonString));
  });
}

// handlebar helpers
const hh = {
  markdown: marked.parse,
  moment: (date, format) => moment.utc(date).format(format),
  count: data => data && data.length,
  dump: (data, spacer) => JSON.stringify(data, null, spacer || null),
  // block helpers
  /* tslint:disable:only-arrow-functions */
  /* tslint:disable:object-literal-shorthand */
  isDoubleArray: function (data, options) {
    return Array.isArray(data[0]) ? options.fn(data) : options.inverse(data);
  },
  if_eq: function (this: void, a, b, opts) {
    return (a === b) ? opts.fn(this) : opts.inverse(this);
  },
  if_any: function (this: void, opts, ...args) {
    return args.some(v => !!v) ? opts.fn(this) : opts.inverse(this);
  },
  ifCond: function (this: void, v1, operator, v2, options) {
    const choose = (pred: boolean) => pred ? options.fn(this) : options.inverse(this);
    switch (operator) {
      // tslint:disable-next-line:triple-equals
      case '==': return choose(v1 == v2);
      case '===': return choose(v1 === v2);
      case '<': return choose(v1 < v2);
      case '<=': return choose(v1 <= v2);
      case '>': return choose(v1 > v2);
      case '>=': return choose(v1 >= v2);
      case '&&': return choose(v1 && v2);
      case '||': return choose(v1 || v2);
      default: return choose(false);
    }
  },
  getRemediation: (description, fixedIn) => {
    // check remediation in the description
    const index = description.indexOf('## Remediation');
    if (index > -1) {
      return marked.parse(description.substring(index));
    }
    // if no remediation in description, try to check in `fixedIn` attribute
    if (Array.isArray(fixedIn) && fixedIn.length) {
      const fixedInJoined = fixedIn.join(', ');
      return marked.parse(`## Remediation\n Fixed in: ${fixedInJoined}`);
    }

    // otherwise, fallback to default message, i.e. No remediation at the moment
    return marked.parse(defaultRemediationText);
  },
  severityLabel: (severity: string) => {
    return severity[0].toUpperCase();
  },
  startsWith: function (str, start, options) {
    return str.startsWith(start) ? options.fn(this) : options.inverse(this);
  },
};

Object.keys(hh).forEach(k => Handlebars.registerHelper(k, hh[k]));
