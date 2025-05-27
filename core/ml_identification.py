            text = data.decode('utf-8', errors='ignore')
            
            # Patterns suspects
            patterns = [
                r'[a-zA-Z0-9]{26,34}\.onion',  # Adresses Tor
                r'bitcoin:([13][a-km-zA-HJ-NP-Z1-9]{25,34})',  # Adresses Bitcoin
                r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',  # Adresses Bitcoin
                r'[a-fA-F0-9]{64}',  # Hashes/clés
                r'BEGIN [A-Z ]+-----.*?-----END [A-Z ]+',  # Clés cryptographiques
                r'(encrypt|decrypt|ransom|payment|bitcoin|recover|restore)',  # Mots-clés
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
                suspicious_strings.extend(matches)
            
            # Nettoyer et dédupliquer
            suspicious_strings = list(set([s for s in suspicious_strings if len(s) > 3]))
            
        except Exception as e:
            self.logger.warning(f"String analysis failed: {e}")
        
        return suspicious_strings[:20]  # Limiter à 20 strings
    
    def _analyze_pe_structure(self, data: bytes) -> Dict[str, Any]:
        """Analyse la structure PE"""
        pe_info = {}
        
        try:
            if data[:2] != b'MZ':
                return pe_info
            
            pe_info['is_pe'] = True
            pe_info['suspicious_sections'] = []
            
            # Rechercher sections suspectes
            suspicious_section_names = [
                b'.UPX0', b'.UPX1', b'.packed', b'.aspack',
                b'.enigma', b'.themida', b'.vmp', b'.vmprotect'
            ]
            
            for section_name in suspicious_section_names:
                if section_name in data:
                    pe_info['suspicious_sections'].append(section_name.decode('utf-8', errors='ignore'))
            
            # Rechercher imports suspects
            suspicious_imports = [
                b'CreateFileW', b'WriteFile', b'CryptEncrypt', b'CryptDecrypt',
                b'RegSetValueEx', b'ShellExecuteW', b'VirtualAlloc'
            ]
            
            pe_info['suspicious_imports'] = []
            for imp in suspicious_imports:
                if imp in data:
                    pe_info['suspicious_imports'].append(imp.decode('utf-8', errors='ignore'))
            
            # Analyser l'entropie des sections
            pe_info['high_entropy_sections'] = 0
            chunk_size = len(data) // 20
            for i in range(20):
                start = i * chunk_size
                end = start + chunk_size
                if end < len(data):
                    chunk_entropy = self.ml_classifier._calculate_entropy(data[start:end])
                    if chunk_entropy > 7.5:
                        pe_info['high_entropy_sections'] += 1
                        
        except Exception as e:
            self.logger.warning(f"PE analysis failed: {e}")
        
        return pe_info
    
    def identify_ransomware_family(self, analysis: FileAnalysis) -> RansomwareSignature:
        """Identifie la famille de ransomware basée sur l'analyse"""
        try:
            # Commencer par les correspondances YARA
            family_from_yara = None
            if 'WannaCry_Indicators' in analysis.yara_matches:
                family_from_yara = 'WannaCry'
            elif 'Locky_Indicators' in analysis.yara_matches:
                family_from_yara = 'Locky'
            
            # Utiliser la prédiction ML comme fallback
            family_from_ml = analysis.ml_prediction.get('family_prediction', 'Unknown')
            ml_confidence = analysis.ml_prediction.get('family_confidence', 0.0)
            
            # Prioriser YARA sur ML
            if family_from_yara:
                final_family = family_from_yara
                final_confidence = 0.95
            else:
                final_family = family_from_ml
                final_confidence = ml_confidence
            
            # Récupérer les informations de la famille
            family_info = self.taxonomy.get_family_info(final_family)
            
            if family_info:
                return RansomwareSignature(
                    family=final_family,
                    variant="Unknown",
                    confidence=final_confidence,
                    indicators={
                        'file_hash': analysis.file_hash,
                        'file_size': analysis.file_size,
                        'entropy': analysis.entropy,
                        'yara_matches': analysis.yara_matches,
                        'suspicious_strings': analysis.suspicious_strings
                    },
                    behavioral_patterns=family_info['behavior_patterns'].split(','),
                    file_markers=family_info['file_extensions'].split(','),
                    network_iocs=family_info['network_indicators'].split(','),
                    encryption_methods=family_info['encryption_algorithm'].split(','),
                    decryption_available=family_info['decryption_tools'] != 'None',
                    threat_level=family_info['threat_level'],
                    first_seen=datetime.now(),
                    last_updated=datetime.now()
                )
            else:
                return RansomwareSignature(
                    family=final_family,
                    variant="Unknown",
                    confidence=final_confidence,
                    indicators={'file_hash': analysis.file_hash},
                    behavioral_patterns=[],
                    file_markers=[],
                    network_iocs=[],
                    encryption_methods=[],
                    decryption_available=False,
                    threat_level="UNKNOWN",
                    first_seen=datetime.now(),
                    last_updated=datetime.now()
                )
                
        except Exception as e:
            self.logger.error(f"Family identification failed: {e}")
            return RansomwareSignature(
                family="Unknown",
                variant="Unknown",
                confidence=0.0,
                indicators={},
                behavioral_patterns=[],
                file_markers=[],
                network_iocs=[],
                encryption_methods=[],
                decryption_available=False,
                threat_level="UNKNOWN",
                first_seen=datetime.now(),
                last_updated=datetime.now()
            )
    
    def batch_analyze_directory(self, directory_path: str, extensions: List[str] = None) -> Dict[str, FileAnalysis]:
        """Analyse par lot d'un répertoire"""
        results = {}
        
        if extensions is None:
            extensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']
        
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Filtrer par extension si spécifié
                    if extensions and not any(file.lower().endswith(ext) for ext in extensions):
                        continue
                    
                    try:
                        analysis = self.analyze_file(file_path)
                        results[file_path] = analysis
                        
                        # Log des détections
                        if analysis.is_malicious:
                            self.logger.warning(f"Malicious file detected: {file_path} (confidence: {analysis.confidence:.2f})")
                            
                    except Exception as e:
                        self.logger.error(f"Failed to analyze {file_path}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Directory analysis failed: {e}")
        
        return results
    
    def generate_detection_report(self, analyses: Dict[str, FileAnalysis]) -> Dict[str, Any]:
        """Génère un rapport de détection"""
        try:
            total_files = len(analyses)
            malicious_files = sum(1 for a in analyses.values() if a.is_malicious)
            
            # Statistiques par famille
            family_stats = defaultdict(int)
            confidence_levels = []
            
            for analysis in analyses.values():
                if analysis.is_malicious:
                    family = analysis.ml_prediction.get('family_prediction', 'Unknown')
                    family_stats[family] += 1
                    confidence_levels.append(analysis.confidence)
            
            # Fichiers les plus suspects
            top_threats = sorted(
                [(path, analysis) for path, analysis in analyses.items() if analysis.is_malicious],
                key=lambda x: x[1].confidence,
                reverse=True
            )[:10]
            
            report = {
                'summary': {
                    'total_files_analyzed': total_files,
                    'malicious_files_detected': malicious_files,
                    'detection_rate': malicious_files / max(total_files, 1),
                    'average_confidence': np.mean(confidence_levels) if confidence_levels else 0.0,
                    'timestamp': datetime.now().isoformat()
                },
                'family_distribution': dict(family_stats),
                'top_threats': [
                    {
                        'file_path': path,
                        'confidence': analysis.confidence,
                        'family': analysis.ml_prediction.get('family_prediction', 'Unknown'),
                        'file_size': analysis.file_size,
                        'entropy': analysis.entropy,
                        'yara_matches': analysis.yara_matches
                    }
                    for path, analysis in top_threats
                ],
                'recommendations': self._generate_recommendations(family_stats, malicious_files)
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return {'error': str(e)}
    
    def _generate_recommendations(self, family_stats: Dict, malicious_count: int) -> List[str]:
        """Génère des recommandations basées sur les détections"""
        recommendations = []
        
        if malicious_count == 0:
            recommendations.append("Aucune menace détectée. Maintenir la surveillance.")
        else:
            recommendations.append(f"{malicious_count} fichiers malveillants détectés. Isolation immédiate recommandée.")
            
            # Recommandations spécifiques par famille
            if 'WannaCry' in family_stats:
                recommendations.append("WannaCry détecté - Vérifier les patchs SMB et isoler les systèmes affectés.")
            
            if 'Ryuk' in family_stats:
                recommendations.append("Ryuk détecté - Attaque ciblée possible, vérifier les mouvements latéraux.")
            
            if 'Locky' in family_stats:
                recommendations.append("Locky détecté - Vérifier les vecteurs d'infection par email/macro.")
            
            # Recommandations générales
            if malicious_count > 5:
                recommendations.append("Nombre élevé de détections - Considérer une réponse d'incident coordonnée.")
            
            recommendations.extend([
                "Effectuer une sauvegarde immédiate des données critiques non affectées.",
                "Activer la surveillance réseau renforcée.",
                "Vérifier l'intégrité des sauvegardes existantes.",
                "Informer l'équipe de sécurité et les parties prenantes."
            ])
        
        return recommendations

# Interface principale pour l'intégration avec R3
def create_advanced_detector(config: Optional[Dict] = None) -> AdvancedRansomwareDetector:
    """Factory function pour créer un détecteur avancé configuré"""
    detector = AdvancedRansomwareDetector()
    
    if config:
        # Configuration personnalisée si nécessaire
        pass
    
    return detector

def analyze_file_for_ransomware(file_path: str, config: Optional[Dict] = None) -> Tuple[bool, RansomwareSignature]:
    """Fonction d'analyse simplifiée pour intégration externe"""
    detector = create_advanced_detector(config)
    
    # Analyser le fichier
    analysis = detector.analyze_file(file_path)
    
    # Identifier la famille si malveillant
    if analysis.is_malicious:
        signature = detector.identify_ransomware_family(analysis)
        return True, signature
    else:
        return False, None

if __name__ == "__main__":
    # Test du module
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        
        print(f"Analyzing file: {file_path}")
        
        detector = create_advanced_detector()
        analysis = detector.analyze_file(file_path)
        
        print(f"\nResults:")
        print(f"  File: {analysis.file_path}")
        print(f"  Hash: {analysis.file_hash}")
        print(f"  Size: {analysis.file_size} bytes")
        print(f"  Type: {analysis.file_type}")
        print(f"  Entropy: {analysis.entropy:.2f}")
        print(f"  Malicious: {analysis.is_malicious}")
        print(f"  Confidence: {analysis.confidence:.2f}")
        
        if analysis.yara_matches:
            print(f"  YARA matches: {', '.join(analysis.yara_matches)}")
        
        if analysis.suspicious_strings:
            print(f"  Suspicious strings: {len(analysis.suspicious_strings)} found")
        
        if analysis.is_malicious:
            signature = detector.identify_ransomware_family(analysis)
            print(f"\nRansomware Family: {signature.family}")
            print(f"  Confidence: {signature.confidence:.2f}")
            print(f"  Threat Level: {signature.threat_level}")
            print(f"  Decryption Available: {signature.decryption_available}")
            
            if signature.behavioral_patterns:
                print(f"  Behavioral Patterns: {', '.join(signature.behavioral_patterns)}")
    else:
        print("Usage: python ml_identification.py <file_path>")
        print("Example: python ml_identification.py /path/to/suspicious/file.exe")
