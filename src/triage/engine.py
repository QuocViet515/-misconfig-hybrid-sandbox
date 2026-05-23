import json
import logging
import argparse
from pathlib import Path
from typing import List

from . import TriageEngine
from ..models import NormalizedFinding, TriageDecision

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_findings(input_file: str) -> List[NormalizedFinding]:
    logger.info(f"Loading findings from {input_file}")
    with open(input_file, "r") as f:
        data = json.load(f)

    if isinstance(data, dict):
        findings_data = data.get('findings', [])
    else:
        findings_data = data

    findings = []
    for finding_dict in findings_data:
        try:
            finding = NormalizedFinding(**finding_dict)
            findings.append(finding)
        except Exception as e:
            logger.warning(f"Failed to parse finding: {str(e)}")
    
    logger.info(f"Loaded {len(findings)} findings")
    return findings

def save_decisions(decisions: List[TriageDecision], output_file: str) -> None:
    logger.info(f"Saving {len(decisions)} decisions to {output_file}")

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    decisions_data = []
    for decision in decisions:
        decision_dict = {
            'finding_id': decision.finding_id,
            'recommendation': decision.recommendation,
            'confidence_score': decision.confidence_score,
            'reasoning': decision.reasoning,
            'metadata': decision.metadata,
            'created_at': decision.created_at.isoformat() if hasattr(decision, 'created_at') else None,
        }
        decisions_data.append(decision_dict)

    with open(output_file, 'w') as f:
        json.dump({
            'total_decisions': len(decisions_data),
            'decisions': decisions_data,
        }, f, indent=2)
    
    logger.info(f"Triage decisions saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(
    description="Run triage engine on findings"
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Input findings JSON file'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output decisions JSON file'
    )
    parser.add_argument(
        '--auto-remediate-threshold',
        default='LOW',
        help='Severity threshold for auto-remediation (LOW, MEDIUM, HIGH, CRITICAL)'
    )
    parser.add_argument(
        '--high-risk-resources',
        default='prod,production',
        help='Comma-separated list of high-risk resource patterns'
    )
    parser.add_argument(
        '--log-level',
        default='INFO',
        help='Logging level (DEBUG, INFO, WARNING, ERROR)'
    )

    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))

    try:
        # Load findings
        findings = load_findings(args.input)
        if not findings:
            logger.warning("No findings to triage")
            return
        
        # Create engine with config
        config = {
            'auto_remediate_threshold': args.auto_remediate_threshold,
            'high_risk_resources': [r.strip() for r in args.high_risk_resources.split(',')],
        }
        engine = TriageEngine(config=config)
        
        logger.info("=" * 80)
        logger.info("TRIAGE ENGINE - PROCESSING FINDINGS")
        logger.info("=" * 80)
        
        # Triage findings
        decisions = engine.triage_batch(findings)
        
        # Get summary
        summary = engine.get_summary(decisions)
        logger.info(f"Triage Summary:")
        logger.info(f"  Total decisions: {summary['total_decisions']}")
        logger.info(f"  Auto-remediate: {summary['auto_remediate']}")
        logger.info(f"  Manual review: {summary['manual_review']}")
        logger.info(f"  Ignore: {summary['ignore']}")
        logger.info(f"  Average confidence: {summary['avg_confidence_score']:.2%}")
        
        # Save decisions
        save_decisions(decisions, args.output)
        
        logger.info("=" * 80)
        logger.info("TRIAGE ENGINE - COMPLETE")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Triage engine failed: {str(e)}", exc_info=True)
        raise
    

if __name__ == "__main__":
    main()