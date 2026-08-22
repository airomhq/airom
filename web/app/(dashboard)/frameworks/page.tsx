"use client";

import React from "react";
import Link from "next/link";
import { ShieldAlert, BookOpen, ExternalLink, CheckCircle2, ArrowRight } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../../components/ui/card";
import { Badge } from "../../../components/ui/badge";
import { Button } from "../../../components/ui/button";

const frameworksList = [
  {
    id: "colorado-ai-act",
    name: "Colorado AI Act (SB 24-205)",
    jurisdiction: "Colorado, USA",
    effectiveDate: "February 1, 2026",
    authority: "Colorado Attorney General",
    citation: "C.R.S. § 6-1-1701 et seq.",
    summary: "Requires deployers and developers of high-risk artificial intelligence systems to implement risk management programs, annual impact assessments, consumer disclosures, and reporting of algorithmic discrimination within 90 days.",
    controlsCount: 4,
    status: "active",
  },
  {
    id: "nyc-ll144",
    name: "NYC Local Law 144 (AEDT)",
    jurisdiction: "New York City, USA",
    effectiveDate: "July 5, 2023",
    authority: "NYC Department of Consumer and Worker Protection (DCWP)",
    citation: "NYC Admin. Code § 20-870 et seq.",
    summary: "Prohibits employers from using an Automated Employment Decision Tool (AEDT) to screen candidates unless the tool has undergone an independent annual bias audit and candidates receive a 10-business-day advance notice.",
    controlsCount: 4,
    status: "active",
  },
  {
    id: "ca-ab2013",
    name: "California AB 2013 (Training Data Transparency)",
    jurisdiction: "California, USA",
    effectiveDate: "January 1, 2026",
    authority: "California Privacy Protection Agency (CPPA)",
    citation: "Cal. Civ. Code § 1798.500 et seq.",
    summary: "Requires developers of generative AI systems to post a high-level summary of datasets used to train the system, including source provenance, licensing terms, and whether the data includes personal information or biometric data.",
    controlsCount: 2,
    status: "active",
  },
  {
    id: "illinois-bipa",
    name: "Illinois BIPA (740 ILCS 14)",
    jurisdiction: "Illinois, USA",
    effectiveDate: "In Effect (Private Right of Action)",
    authority: "Illinois Courts ($1,000 - $5,000 liquidated statutory damages per violation)",
    citation: "740 ILCS 14/15(a)-(e)",
    summary: "Regulates the collection, capture, purchase, and storage of biometric identifiers and biometric information. Requires written retention schedules, destruction policies, and bans profiting from biometric data.",
    controlsCount: 5,
    status: "active",
  },
  {
    id: "texas-traiga",
    name: "Texas TRAIGA (Gov Code § 2054)",
    jurisdiction: "Texas, USA",
    effectiveDate: "September 1, 2025",
    authority: "Texas Department of Information Resources (DIR)",
    citation: "Tex. Gov't Code § 2054.601-604",
    summary: "Establishes state automated decision system standards, state registry disclosures, and mandatory impact evaluations to prevent discrimination in public benefit, healthcare, and employment determinations.",
    controlsCount: 4,
    status: "active",
  },
  {
    id: "virginia-vcdpa",
    name: "Virginia VCDPA (§ 59.1-575)",
    jurisdiction: "Virginia, USA",
    effectiveDate: "In Effect",
    authority: "Office of the Attorney General of Virginia",
    citation: "Va. Code Ann. § 59.1-575 to § 59.1-584",
    summary: "Mandates Data Protection Assessments (DPAs) for automated decision-making and profiling that presents a reasonably foreseeable risk of unfair or deceptive treatment, financial, physical, or reputational injury.",
    controlsCount: 4,
    status: "active",
  },
  {
    id: "nist-ai-rmf",
    name: "NIST AI Risk Management Framework 1.0",
    jurisdiction: "United States (Federal Standard)",
    effectiveDate: "January 2023",
    authority: "National Institute of Standards and Technology (NIST)",
    citation: "NIST AI 100-1",
    summary: "Voluntary guidance to improve the ability of organizations to incorporate trustworthiness considerations into the design, development, use, and evaluation of AI products, services, and systems (GOVERN, MAP, MEASURE, MANAGE).",
    controlsCount: 11,
    status: "active",
  },
  {
    id: "owasp-agentic",
    name: "OWASP Top 10 for Agentic AI",
    jurisdiction: "International Security Standard",
    effectiveDate: "2026",
    authority: "OWASP Foundation",
    citation: "OWASP-ASI-2026",
    summary: "Security risk model for autonomous and multi-agent AI systems, addressing agent goal hijacking, tool execution abuse, broken boundary controls, unsafe deserialization, and memory poisoning.",
    controlsCount: 10,
    status: "active",
  },
];

export default function FrameworksPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Statutory & Federal AI Frameworks</h1>
        <p className="text-sm text-gray-400">
          Embedded regulatory intelligence packs with zero-network deterministic code-to-control mapping.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {frameworksList.map((fw) => (
          <Card key={fw.id} className="border-gray-800 bg-gray-900/60 flex flex-col justify-between">
            <CardHeader>
              <div className="flex items-center justify-between gap-2">
                <Badge variant="met">{fw.jurisdiction}</Badge>
                <span className="text-[11px] font-mono text-gray-500">{fw.citation}</span>
              </div>
              <CardTitle className="text-base text-white mt-2">{fw.name}</CardTitle>
              <CardDescription className="text-xs text-gray-400 mt-1 leading-relaxed">
                {fw.summary}
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="rounded bg-gray-950 p-3 text-xs space-y-1.5 border border-gray-800">
                <div className="flex justify-between text-gray-400">
                  <span>Enforcing Authority:</span>
                  <span className="text-gray-200 font-medium">{fw.authority}</span>
                </div>
                <div className="flex justify-between text-gray-400">
                  <span>Effective Date:</span>
                  <span className="text-emerald-400 font-mono">{fw.effectiveDate}</span>
                </div>
                <div className="flex justify-between text-gray-400">
                  <span>Automated Control Directives:</span>
                  <span className="text-blue-400 font-mono font-bold">{fw.controlsCount} controls</span>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
