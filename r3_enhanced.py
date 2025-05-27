                print(f"Confidence: {id_results.get('confidence', 0):.1%}")
            
            if 'response' in incident_data['phases']:
                resp_results = incident_data['phases']['response']['results']
                print(f"Response Strategy: {resp_results.get('response_strategy', 'unknown')}")
                if resp_results.get('decryption_attempted'):
                    print(f"Decryption Success: {resp_results.get('decryption_success', False)}")
            
            if 'reporting' in incident_data['phases']:
                report_results = incident_data['phases']['reporting']['results']
                if report_results.get('report_generated'):
                    print(f"Report Generated: {report_results['report_path']}")
        
        else:
            print("❌ Invalid arguments. Use --help for usage information.")
        
        # Arrêt propre
        await r3.shutdown()
        
    except KeyboardInterrupt:
        print("\n⚠️  R3 Enhanced interrupted by user")
    except Exception as e:
        print(f"❌ R3 Enhanced error: {e}")
        logging.exception("R3 Enhanced critical error")

if __name__ == "__main__":
    # Exécuter R3 Enhanced
    asyncio.run(main())
