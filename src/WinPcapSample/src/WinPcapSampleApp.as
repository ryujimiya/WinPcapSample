package
{
    import flash.desktop.NativeApplication;
    import flash.events.Event;
    import flash.events.MouseEvent;
    import livefan.winpcap.ResultGetArrival;
    import mx.events.FlexEvent;
	import mx.controls.Alert;
    
    /**
     *
     * @author Owner
     */
    public class WinPcapSampleApp extends WinPcapSampleAppView
    {
        private var _defWidth:int = 0;
        private var _defHeight:int = 0;
		private var _networkName:String = "";
		private var _networkSettingsWin:NetworkSettingsWin = null;

		/**
		 * コンストラクタ
		 */
        public function WinPcapSampleApp()
        {
            super();
            addEventListener(FlexEvent.APPLICATION_COMPLETE, initApp);
            addEventListener(Event.CLOSING, closing);
        }

		/**
		 * アプリが起動した
		 * @param	e
		 */
        private function initApp(e:FlexEvent):void 
        {
            _defWidth = this.stage.stageWidth;
            _defHeight = this.stage.stageHeight;
            this.width = 200;
            this.height = 400;
            this.visible = true;
            btnBasicDumpDemo.addEventListener(MouseEvent.CLICK, btnBasicDumpDemoClick);
			btnNetworkSettings.addEventListener(MouseEvent.CLICK, btnNetworkSettingsClick);
            btnCaptureThreadDemo.addEventListener(MouseEvent.CLICK, btnCaptureThreadDemoClick);
            btnPcapNextDemo.addEventListener(MouseEvent.CLICK, btnPcapNextDemoClick);
            btnGatherStatisticsDemo.addEventListener(MouseEvent.CLICK, btnGatherStatisticsDemoClick);
            btnSendPacketDemo.addEventListener(MouseEvent.CLICK, btnSendPacketDemoClick);
        }
        
		/**
		 * アプリが閉じられようとしている
		 * @param	e
		 */
        private function closing(e:Event):void 
        {
            
        }
    
		/**
		 * Basic Dump Demoボタンがクリックされた
		 * @param	e
		 */
        private function btnBasicDumpDemoClick(e:MouseEvent):void 
        {
            var basicDumpWin:BasicDumpDemoWin = new BasicDumpDemoWin();
            basicDumpWin.title = "BasicDump Demo";
            basicDumpWin.width = _defWidth;
            basicDumpWin.height = _defHeight;
            basicDumpWin.open();
        }

		/**
		 * Network Settingsボタンがクリックされた
		 * @param	e
		 */
        private function btnNetworkSettingsClick(e:MouseEvent):void 
        {
            if (_networkSettingsWin != null)
            {
                _networkSettingsWin.orderToFront();
                return;
            }
            _networkSettingsWin = new NetworkSettingsWin();
            _networkSettingsWin.title = "Network Settings";
            _networkSettingsWin.width = _defWidth;
            _networkSettingsWin.height = _defHeight;
			_networkSettingsWin.networkName = _networkName;
            _networkSettingsWin.open(true);
            _networkSettingsWin.addEventListener(Event.CLOSE, networkSettingsWinClose);
			
        }
		
        /**
         * ネットワーク設定ウィンドウが終了した
         * @param e
         */
        private function networkSettingsWinClose(e:Event):void
		{
			_networkName = _networkSettingsWin.networkName;
			_networkSettingsWin = null;
		}

		/**
		 * Capture Thread Demoボタンがクリックされた
		 * @param	e
		 */
        private function btnCaptureThreadDemoClick(e:MouseEvent):void 
        {
			if (_networkName == "")
			{
				Alert.show("finish Network Settings first.");
				return;
			}
            var captureThreadDemoWin:CaptureThreadDemoWin = new CaptureThreadDemoWin(_networkName);
            captureThreadDemoWin.title = "CaptureThread Demo";
            captureThreadDemoWin.width = _defWidth;
            captureThreadDemoWin.height = _defHeight;
            captureThreadDemoWin.open();
        }
        
		/**
		 * PcapNext Demoボタンがクリックされた
		 * @param	e
		 */
        private function btnPcapNextDemoClick(e:MouseEvent):void 
        {
			if (_networkName == "")
			{
				Alert.show("finish Network Settings first.");
				return;
			}
            var pcapNextDemoWin:PcapNextDemoWin = new PcapNextDemoWin(_networkName);
            pcapNextDemoWin.title = "PcapNext Demo";
            pcapNextDemoWin.width = _defWidth;
            pcapNextDemoWin.height = _defHeight;
            pcapNextDemoWin.open();
        }
        
		/**
		 * Gather Statistics Demoボタンがクリックされた
		 * @param	e
		 */
        private function btnGatherStatisticsDemoClick(e:MouseEvent):void 
        {
			if (_networkName == "")
			{
				Alert.show("finish Network Settings first.");
				return;
			}
            var gatherStatistcsWin:GatherStatistcsWin = new GatherStatistcsWin(_networkName);
            gatherStatistcsWin.title = "Gathering Statistcs Demo";
            gatherStatistcsWin.width = _defWidth;
            gatherStatistcsWin.height = _defHeight;
            gatherStatistcsWin.open();
        }
        
		/**
		 * Send Packet Demoボタンがクリックされた
		 * @param	e
		 */
        private function btnSendPacketDemoClick(e:MouseEvent):void 
        {
			if (_networkName == "")
			{
				Alert.show("finish Network Settings first.");
				return;
			}
            var sendPacketDemoWin:SendPacketDemoWin = new SendPacketDemoWin(_networkName);
            sendPacketDemoWin.title = "Send Packet Demo";
            sendPacketDemoWin.width = _defWidth;
            sendPacketDemoWin.height = _defHeight;
            sendPacketDemoWin.open();
        }
        
    }

}