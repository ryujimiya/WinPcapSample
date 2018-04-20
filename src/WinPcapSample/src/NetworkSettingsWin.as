package 
{
    import flash.events.Event;
    import flash.utils.ByteArray;
    import livefan.packet.IpPacket;
    import livefan.packet.Ipv4Packet;
    import livefan.packet.Ipv6Packet;
    import livefan.packet.Packet;
    import livefan.packet.PacketUtil;
    import livefan.packet.TcpPacket;
    import livefan.packet.UdpPacket;
    import livefan.winpcap.PcapAddr;
    import livefan.winpcap.PcapDefine;
    import livefan.winpcap.PcapDumper;
    import livefan.winpcap.PcapHandle;
    import livefan.winpcap.PcapIf;
    import livefan.winpcap.PcapPktHdr;
    import livefan.winpcap.PcapStat;
    import livefan.winpcap.ResultAllDevs;
    import livefan.winpcap.ResultGetArrival;
    import livefan.winpcap.ResultPcap;
    import livefan.winpcap.ResultPcapDump;
    import livefan.winpcap.ResultPcapNext;
    import livefan.winpcap.ResultPcapStats;
    import livefan.winpcap.SockAddr;
    import livefan.winpcap.Timeval;
    import livefan.winpcap.WinPcapExtension;
    import livefan.winpcap.WinPcapExtensionEvent;
    import mx.collections.ArrayCollection;
    import mx.controls.Alert;
    import mx.utils.StringUtil;
    import mx.events.AIREvent;
    import spark.events.IndexChangeEvent;

	/**
	 * ...
	 * @author 
	 */
	public class NetworkSettingsWin extends NetworkSettingsWinView 
	{
		/**
		 * 選択されたネットワーク名
		 */
		private var _networkName:String = "";
        /**
         * WinPcapネイティブ拡張インスタンス
         */
        private var _extension:WinPcapExtension = null;
        /**
         * ネットワークインターフェースインスタンス
         */
        private var _pcapIf:PcapIf = null;
		
		public function get networkName():String
		{
			return _networkName;
		}
		public function set networkName(value:String):void
		{
			_networkName = value;
		}

        /**
         * コンストラクタ
         */
        public function NetworkSettingsWin()
        {
            super();
            addEventListener(AIREvent.WINDOW_COMPLETE, initWin);
            addEventListener(Event.CLOSING, closing);
        }

        /**
         * ウィンドウが初期化された
         * @param e
         */
        private function initWin(e:AIREvent):void 
        {
            // WinPcap拡張インスタンスの生成
            _extension = new WinPcapExtension();

            listNetworkIf.addEventListener(IndexChangeEvent.CHANGE, listNetworkIfIndexChange);
            setupNetworkIfList();
			listNetworkIfSelect();
        }

        /**
         * ウィンドウが閉じられようとしている
         * @param e
         */
        private function closing(e:Event):void 
        {
            _extension.dispose();
        }
		
        /**
         * ネットワークインターフェース一覧をセットアップ
         */
        private function setupNetworkIfList():void
        {
			/*
            if (_pcapHandle != null)
            {
                return;
            }
			*/
            var source:String = PcapDefine.PCAP_SRC_IF_STRING;
            
            // ネットワークインターフェースの一覧を取得
            var resAllDevs:ResultAllDevs = _extension.pcapFindAllDevsEx(source, null);
            if (resAllDevs.retVal != 0)
            {
                Alert.show(resAllDevs.errBuf, "", Alert.OK, this);
                return;
            }
            
            // ネットワークインターフェースをリストに登録
            var dataProvider:ArrayCollection = new ArrayCollection();
            var pcapIfs:PcapIf = resAllDevs.pcapIfs;
            for (var pcapIf:PcapIf = pcapIfs; pcapIf != null; pcapIf = pcapIf.next)
            {
                var name:String = pcapIf.name;
                var description:String = pcapIf.description;
                var addresses:PcapAddr = pcapIf.addresses;
                var labelStr:String = description;
                dataProvider.addItem( { label: labelStr , data:pcapIf } );
            }
            listNetworkIf.dataProvider = dataProvider;
            
            // インターフェース一覧を解放
            resAllDevs.dispose();
        }
		
		/**
		 * ネットワーク名に対応したリストの項目を選択する
		 */
		private function listNetworkIfSelect():void
		{
			var dataProvider:ArrayCollection = listNetworkIf.dataProvider as ArrayCollection;
			if (dataProvider == null)
			{
				return;
			}
			var tgtIndex:int = -1;
			for (var i:int = 0; i < dataProvider.length; i++)
			{
				var item:Object = dataProvider.getItemAt(i);
                var pcapIf:PcapIf = item.data;
                if (pcapIf == null)
                {
                    continue;
                }
                var name:String = pcapIf.name;
				if (name == _networkName)
				{
					tgtIndex = i;
					break;
				}
			}
			listNetworkIf.selectedIndex = tgtIndex;
		}

        /**
         * ネットワークインターフェース一覧リストの選択しているインデックスが変わった
         * @param e
         */
        private function listNetworkIfIndexChange(e:IndexChangeEvent):void 
        {
            if (e.newIndex == -1)
            {
                return;
            }
            var dataProvider:ArrayCollection = listNetworkIf.dataProvider as ArrayCollection;
            if (dataProvider == null)
            {
                return;
            }
            var item:Object = dataProvider.getItemAt(e.newIndex);
            if (item == null)
            {
                return;
            }
            var pcapIf:PcapIf = item.data;
            if (pcapIf == null)
            {
                return;
            }
            var name:String = pcapIf.name;
            var description:String = pcapIf.description;
            var addresses:PcapAddr = pcapIf.addresses;
            var flags:uint = pcapIf.flags;
			
			_networkName = name;
            
            var newlineStr:String = "\r\n";
            var text:String = "";
            text += "name: " + name + newlineStr;
            text += "description: " + description + newlineStr;
            text += "loopback: " + ((flags & PcapDefine.PCAP_IF_LOOPBACK)? "yes":"no") + newlineStr;
            var addressCounter:int = 0;
            for (var addr:PcapAddr = addresses; addr != null; addr = addr.next)
            {
                text += "(" + (addressCounter + 1) + ")" + newlineStr;
                if (addr.addr != null && addr.addr.saFamily != 0)
                {
                    text += "  address: " + newlineStr;
                    text += "    sa family: " + saFamilyStr(addr.addr.saFamily) + newlineStr;
                    text += "    address: " + getGuiStrAddr(_extension, addr.addr) + newlineStr;
                }
                if (addr.netMask != null && addr.netMask.saFamily != 0)
                {
                    text += "  netmask: " + newlineStr;
                    text += "    sa family: " + saFamilyStr(addr.netMask.saFamily) + newlineStr;
                    text += "    address: " + getGuiStrAddr(_extension, addr.netMask) + newlineStr;
                }
                if (addr.broadAddr != null && addr.broadAddr.saFamily != 0)
                {
                    text += "  broad address: " + newlineStr;
                    text += "    sa family: " + saFamilyStr(addr.broadAddr.saFamily) + newlineStr;
                    text += "    address: " + getGuiStrAddr(_extension, addr.broadAddr) + newlineStr;
                }
                if (addr.dstAddr != null && addr.dstAddr.saFamily != 0)
                {
                    text += "  dst address: " + newlineStr;
                    text += "    sa family: " + saFamilyStr(addr.dstAddr.saFamily) + newlineStr;
                    text += "    address: " + getGuiStrAddr(_extension, addr.dstAddr) + newlineStr;
                }
                addressCounter++;
            }
            textAreaNetworkIf.text = text;
        }

        /**
         * SockAddrのsaFamily値に対応する文字列を取得する
         * @param saFamily
         * @return
         */
        private static function saFamilyStr(saFamily:uint):String
        {
            if (saFamily == SockAddr.AF_INET)
            {
                return "IPv4";
            }
            else if (saFamily == SockAddr.AF_INET6)
            {
                return "IPv6";
            }
            return saFamily.toString();
        }
		
        /**
         * GUI表示用アドレス文字列を取得する
         * @param extension WinPcapネイティブ拡張インスタンス
         * @param addr ソケットアドレスインスタンス
         * @return
         */
        private static function getGuiStrAddr(extension:WinPcapExtension, addr:SockAddr):String
        {
            var i:int;
            var newlineStr:String = "\r\n";
            var headStr:String = "             ";
            var text:String = "";

            var addrAsBytes:ByteArray = addr.addrAsBytes;
            text = extension.IpAddrByteArrayToString(addr.saFamily, addrAsBytes) + newlineStr;
            text += headStr + "(";
            for (i = 0; i < addrAsBytes.length; i++)
            {
                var val:uint = addrAsBytes[i];
                text += val.toString(16) + " ";
            }
            text += ")";
            return text;
        }
	}

}