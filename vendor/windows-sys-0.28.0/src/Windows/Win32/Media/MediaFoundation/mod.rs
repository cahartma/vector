#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, clashing_extern_declarations, clippy::all)]
#[link(name = "windows")]
extern "system" {
    #[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
    pub fn CreateNamedPropertyStore(ppstore: *mut super::super::UI::Shell::PropertiesSystem::INamedPropertyStore) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
    pub fn CreatePropertyStore(ppstore: *mut super::super::UI::Shell::PropertiesSystem::IPropertyStore) -> ::windows_sys::core::HRESULT;
    pub fn DXVA2CreateDirect3DDeviceManager9(presettoken: *mut u32, ppdevicemanager: *mut IDirect3DDeviceManager9) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Graphics_Direct3D9")]
    pub fn DXVA2CreateVideoService(pdd: super::super::Graphics::Direct3D9::IDirect3DDevice9, riid: *const ::windows_sys::core::GUID, ppservice: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Graphics_Direct3D9")]
    pub fn DXVAHD_CreateDevice(pd3ddevice: super::super::Graphics::Direct3D9::IDirect3DDevice9Ex, pcontentdesc: *const DXVAHD_CONTENT_DESC, usage: DXVAHD_DEVICE_USAGE, pplugin: ::core::option::Option<PDXVAHDSW_Plugin>, ppdevice: *mut IDXVAHD_Device) -> ::windows_sys::core::HRESULT;
    pub fn MFAddPeriodicCallback(callback: ::core::option::Option<MFPERIODICCALLBACK>, pcontext: ::windows_sys::core::IUnknown, pdwkey: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFAllocateSerialWorkQueue(dwworkqueue: u32, pdwworkqueue: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFAllocateWorkQueue(pdwworkqueue: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFAllocateWorkQueueEx(workqueuetype: MFASYNC_WORKQUEUE_TYPE, pdwworkqueue: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFAverageTimePerFrameToFrameRate(unaveragetimeperframe: u64, punnumerator: *mut u32, pundenominator: *mut u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFBeginCreateFile(accessmode: MF_FILE_ACCESSMODE, openmode: MF_FILE_OPENMODE, fflags: MF_FILE_FLAGS, pwszfilepath: super::super::Foundation::PWSTR, pcallback: IMFAsyncCallback, pstate: ::windows_sys::core::IUnknown, ppcancelcookie: *mut ::windows_sys::core::IUnknown) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFBeginRegisterWorkQueueWithMMCSS(dwworkqueueid: u32, wszclass: super::super::Foundation::PWSTR, dwtaskid: u32, pdonecallback: IMFAsyncCallback, pdonestate: ::windows_sys::core::IUnknown) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFBeginRegisterWorkQueueWithMMCSSEx(dwworkqueueid: u32, wszclass: super::super::Foundation::PWSTR, dwtaskid: u32, lpriority: i32, pdonecallback: IMFAsyncCallback, pdonestate: ::windows_sys::core::IUnknown) -> ::windows_sys::core::HRESULT;
    pub fn MFBeginUnregisterWorkQueueWithMMCSS(dwworkqueueid: u32, pdonecallback: IMFAsyncCallback, pdonestate: ::windows_sys::core::IUnknown) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Gdi"))]
    pub fn MFCalculateBitmapImageSize(pbmih: *const super::super::Graphics::Gdi::BITMAPINFOHEADER, cbbufsize: u32, pcbimagesize: *mut u32, pbknown: *mut super::super::Foundation::BOOL) -> ::windows_sys::core::HRESULT;
    pub fn MFCalculateImageSize(guidsubtype: *const ::windows_sys::core::GUID, unwidth: u32, unheight: u32, pcbimagesize: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFCancelCreateFile(pcancelcookie: ::windows_sys::core::IUnknown) -> ::windows_sys::core::HRESULT;
    pub fn MFCancelWorkItem(key: u64) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCombineSamples(psample: IMFSample, psampletoadd: IMFSample, dwmaxmergeddurationinms: u32, pmerged: *mut super::super::Foundation::BOOL) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCompareFullToPartialMediaType(pmftypefull: IMFMediaType, pmftypepartial: IMFMediaType) -> super::super::Foundation::BOOL;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFConvertColorInfoFromDXVA(ptoformat: *mut MFVIDEOFORMAT, dwfromdxva: u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFConvertColorInfoToDXVA(pdwtodxva: *mut u32, pfromformat: *const MFVIDEOFORMAT) -> ::windows_sys::core::HRESULT;
    pub fn MFConvertFromFP16Array(pdest: *mut f32, psrc: *const u16, dwcount: u32) -> ::windows_sys::core::HRESULT;
    pub fn MFConvertToFP16Array(pdest: *mut u16, psrc: *const f32, dwcount: u32) -> ::windows_sys::core::HRESULT;
    pub fn MFCopyImage(pdest: *mut u8, ldeststride: i32, psrc: *const u8, lsrcstride: i32, dwwidthinbytes: u32, dwlines: u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreate2DMediaBuffer(dwwidth: u32, dwheight: u32, dwfourcc: u32, fbottomup: super::super::Foundation::BOOL, ppbuffer: *mut IMFMediaBuffer) -> ::windows_sys::core::HRESULT;
    pub fn MFCreate3GPMediaSink(pibytestream: IMFByteStream, pvideomediatype: IMFMediaType, paudiomediatype: IMFMediaType, ppimediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateAC3MediaSink(ptargetbytestream: IMFByteStream, paudiomediatype: IMFMediaType, ppmediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateADTSMediaSink(ptargetbytestream: IMFByteStream, paudiomediatype: IMFMediaType, ppmediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_Media_DirectShow"))]
    pub fn MFCreateAMMediaTypeFromMFMediaType(pmftype: IMFMediaType, guidformatblocktype: ::windows_sys::core::GUID, ppamtype: *mut *mut super::DirectShow::AM_MEDIA_TYPE) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFContentInfo(ppicontentinfo: *mut IMFASFContentInfo) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFIndexer(ppiindexer: *mut IMFASFIndexer) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFIndexerByteStream(picontentbytestream: IMFByteStream, cbindexstartoffset: u64, piindexbytestream: *mut IMFByteStream) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFMediaSink(pibytestream: IMFByteStream, ppimediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateASFMediaSinkActivate(pwszfilename: super::super::Foundation::PWSTR, pcontentinfo: IMFASFContentInfo, ppiactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFMultiplexer(ppimultiplexer: *mut IMFASFMultiplexer) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFProfile(ppiprofile: *mut IMFASFProfile) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFProfileFromPresentationDescriptor(pipd: IMFPresentationDescriptor, ppiprofile: *mut IMFASFProfile) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFSplitter(ppisplitter: *mut IMFASFSplitter) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFStreamSelector(piasfprofile: IMFASFProfile, ppselector: *mut IMFASFStreamSelector) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFStreamingMediaSink(pibytestream: IMFByteStream, ppimediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateASFStreamingMediaSinkActivate(pbytestreamactivate: IMFActivate, pcontentinfo: IMFASFContentInfo, ppiactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateAVIMediaSink(pibytestream: IMFByteStream, pvideomediatype: IMFMediaType, paudiomediatype: IMFMediaType, ppimediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateAggregateSource(psourcecollection: IMFCollection, ppaggsource: *mut IMFMediaSource) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateAlignedMemoryBuffer(cbmaxlength: u32, cbaligment: u32, ppbuffer: *mut IMFMediaBuffer) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateAsyncResult(punkobject: ::windows_sys::core::IUnknown, pcallback: IMFAsyncCallback, punkstate: ::windows_sys::core::IUnknown, ppasyncresult: *mut IMFAsyncResult) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateAttributes(ppmfattributes: *mut IMFAttributes, cinitialsize: u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Media_Audio")]
    pub fn MFCreateAudioMediaType(paudioformat: *const super::Audio::WAVEFORMATEX, ppiaudiomediatype: *mut IMFAudioMediaType) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateAudioRenderer(paudioattributes: IMFAttributes, ppsink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateAudioRendererActivate(ppactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateCameraOcclusionStateMonitor(symboliclink: super::super::Foundation::PWSTR, callback: IMFCameraOcclusionStateReportCallback, occlusionstatemonitor: *mut IMFCameraOcclusionStateMonitor) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateCollection(ppimfcollection: *mut IMFCollection) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateContentDecryptorContext(guidmediaprotectionsystemid: *const ::windows_sys::core::GUID, pd3dmanager: IMFDXGIDeviceManager, pcontentprotectiondevice: IMFContentProtectionDevice, ppcontentdecryptorcontext: *mut IMFContentDecryptorContext) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateContentProtectionDevice(protectionsystemid: *const ::windows_sys::core::GUID, contentprotectiondevice: *mut IMFContentProtectionDevice) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateCredentialCache(ppcache: *mut IMFNetCredentialCache) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Graphics_Direct3D12")]
    pub fn MFCreateD3D12SynchronizationObject(pdevice: super::super::Graphics::Direct3D12::ID3D12Device, riid: *const ::windows_sys::core::GUID, ppvsyncobject: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateDXGIDeviceManager(resettoken: *mut u32, ppdevicemanager: *mut IMFDXGIDeviceManager) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateDXGISurfaceBuffer(riid: *const ::windows_sys::core::GUID, punksurface: ::windows_sys::core::IUnknown, usubresourceindex: u32, fbottomupwhenlinear: super::super::Foundation::BOOL, ppbuffer: *mut IMFMediaBuffer) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateDXSurfaceBuffer(riid: *const ::windows_sys::core::GUID, punksurface: ::windows_sys::core::IUnknown, fbottomupwhenlinear: super::super::Foundation::BOOL, ppbuffer: *mut IMFMediaBuffer) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateDeviceSource(pattributes: IMFAttributes, ppsource: *mut IMFMediaSource) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateDeviceSourceActivate(pattributes: IMFAttributes, ppactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_System_Com"))]
    pub fn MFCreateEncryptedMediaExtensionsStoreActivate(pmphost: IMFPMPHostApp, objectstream: super::super::System::Com::IStream, classid: super::super::Foundation::PWSTR, activate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateEventQueue(ppmediaeventqueue: *mut IMFMediaEventQueue) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateExtendedCameraIntrinsicModel(distortionmodeltype: MFCameraIntrinsic_DistortionModelType, ppextendedcameraintrinsicmodel: *mut IMFExtendedCameraIntrinsicModel) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateExtendedCameraIntrinsics(ppextendedcameraintrinsics: *mut IMFExtendedCameraIntrinsics) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateFMPEG4MediaSink(pibytestream: IMFByteStream, pvideomediatype: IMFMediaType, paudiomediatype: IMFMediaType, ppimediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateFile(accessmode: MF_FILE_ACCESSMODE, openmode: MF_FILE_OPENMODE, fflags: MF_FILE_FLAGS, pwszfileurl: super::super::Foundation::PWSTR, ppibytestream: *mut IMFByteStream) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Media_DxMediaObjects")]
    pub fn MFCreateLegacyMediaBufferOnMFMediaBuffer(psample: IMFSample, pmfmediabuffer: IMFMediaBuffer, cboffset: u32, ppmediabuffer: *mut super::DxMediaObjects::IMediaBuffer) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_System_Com")]
    pub fn MFCreateMFByteStreamOnStream(pstream: super::super::System::Com::IStream, ppbytestream: *mut IMFByteStream) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMFByteStreamOnStreamEx(punkstream: ::windows_sys::core::IUnknown, ppbytestream: *mut IMFByteStream) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMFByteStreamWrapper(pstream: IMFByteStream, ppstreamwrapper: *mut IMFByteStream) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateMFVideoFormatFromMFMediaType(pmftype: IMFMediaType, ppmfvf: *mut *mut MFVIDEOFORMAT, pcbsize: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMP3MediaSink(ptargetbytestream: IMFByteStream, ppmediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMPEG4MediaSink(pibytestream: IMFByteStream, pvideomediatype: IMFMediaType, paudiomediatype: IMFMediaType, ppimediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMediaBufferFromMediaType(pmediatype: IMFMediaType, llduration: i64, dwminlength: u32, dwminalignment: u32, ppbuffer: *mut IMFMediaBuffer) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMediaBufferWrapper(pbuffer: IMFMediaBuffer, cboffset: u32, dwlength: u32, ppbuffer: *mut IMFMediaBuffer) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_System_Com", feature = "Win32_System_Com_StructuredStorage"))]
    pub fn MFCreateMediaEvent(met: u32, guidextendedtype: *const ::windows_sys::core::GUID, hrstatus: ::windows_sys::core::HRESULT, pvvalue: *const super::super::System::Com::StructuredStorage::PROPVARIANT, ppevent: *mut IMFMediaEvent) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateMediaExtensionActivate(szactivatableclassid: super::super::Foundation::PWSTR, pconfiguration: ::windows_sys::core::IUnknown, riid: *const ::windows_sys::core::GUID, ppvobject: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMediaSession(pconfiguration: IMFAttributes, ppmediasession: *mut IMFMediaSession) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMediaType(ppmftype: *mut IMFMediaType) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMediaTypeFromProperties(punkstream: ::windows_sys::core::IUnknown, ppmediatype: *mut IMFMediaType) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMediaTypeFromRepresentation(guidrepresentation: ::windows_sys::core::GUID, pvrepresentation: *const ::core::ffi::c_void, ppimediatype: *mut IMFMediaType) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMemoryBuffer(cbmaxlength: u32, ppbuffer: *mut IMFMediaBuffer) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMuxSink(guidoutputsubtype: ::windows_sys::core::GUID, poutputattributes: IMFAttributes, poutputbytestream: IMFByteStream, ppmuxsink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMuxStreamAttributes(pattributestomux: IMFCollection, ppmuxattribs: *mut IMFAttributes) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMuxStreamMediaType(pmediatypestomux: IMFCollection, ppmuxmediatype: *mut IMFMediaType) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateMuxStreamSample(psamplestomux: IMFCollection, ppmuxsample: *mut IMFSample) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateNetSchemePlugin(riid: *const ::windows_sys::core::GUID, ppvhandler: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreatePMPMediaSession(dwcreationflags: u32, pconfiguration: IMFAttributes, ppmediasession: *mut IMFMediaSession, ppenableractivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    pub fn MFCreatePMPServer(dwcreationflags: u32, pppmpserver: *mut IMFPMPServer) -> ::windows_sys::core::HRESULT;
    pub fn MFCreatePresentationClock(pppresentationclock: *mut IMFPresentationClock) -> ::windows_sys::core::HRESULT;
    pub fn MFCreatePresentationDescriptor(cstreamdescriptors: u32, apstreamdescriptors: *const IMFStreamDescriptor, pppresentationdescriptor: *mut IMFPresentationDescriptor) -> ::windows_sys::core::HRESULT;
    pub fn MFCreatePresentationDescriptorFromASFProfile(piprofile: IMFASFProfile, ppipd: *mut IMFPresentationDescriptor) -> ::windows_sys::core::HRESULT;
    pub fn MFCreatePropertiesFromMediaType(pmediatype: IMFMediaType, riid: *const ::windows_sys::core::GUID, ppv: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateProtectedEnvironmentAccess(ppaccess: *mut IMFProtectedEnvironmentAccess) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_UI_Shell_PropertiesSystem"))]
    pub fn MFCreateProxyLocator(pszprotocol: super::super::Foundation::PWSTR, pproxyconfig: super::super::UI::Shell::PropertiesSystem::IPropertyStore, ppproxylocator: *mut IMFNetProxyLocator) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateRelativePanelWatcher(videodeviceid: super::super::Foundation::PWSTR, displaymonitordeviceid: super::super::Foundation::PWSTR, pprelativepanelwatcher: *mut IMFRelativePanelWatcher) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateRemoteDesktopPlugin(ppplugin: *mut IMFRemoteDesktopPlugin) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSample(ppimfsample: *mut IMFSample) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSampleCopierMFT(ppcopiermft: *mut IMFTransform) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSampleGrabberSinkActivate(pimfmediatype: IMFMediaType, pimfsamplegrabbersinkcallback: IMFSampleGrabberSinkCallback, ppiactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSensorActivityMonitor(pcallback: IMFSensorActivitiesReportCallback, ppactivitymonitor: *mut IMFSensorActivityMonitor) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateSensorGroup(sensorgroupsymboliclink: super::super::Foundation::PWSTR, ppsensorgroup: *mut IMFSensorGroup) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateSensorProfile(profiletype: *const ::windows_sys::core::GUID, profileindex: u32, constraints: super::super::Foundation::PWSTR, ppprofile: *mut IMFSensorProfile) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSensorProfileCollection(ppsensorprofile: *mut IMFSensorProfileCollection) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSensorStream(streamid: u32, pattributes: IMFAttributes, pmediatypecollection: IMFCollection, ppstream: *mut IMFSensorStream) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_System_Com", feature = "Win32_System_Com_StructuredStorage"))]
    pub fn MFCreateSequencerSegmentOffset(dwid: u32, hnsoffset: i64, pvarsegmentoffset: *mut super::super::System::Com::StructuredStorage::PROPVARIANT) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSequencerSource(preserved: ::windows_sys::core::IUnknown, ppsequencersource: *mut IMFSequencerSource) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSimpleTypeHandler(pphandler: *mut IMFMediaTypeHandler) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSinkWriterFromMediaSink(pmediasink: IMFMediaSink, pattributes: IMFAttributes, ppsinkwriter: *mut IMFSinkWriter) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateSinkWriterFromURL(pwszoutputurl: super::super::Foundation::PWSTR, pbytestream: IMFByteStream, pattributes: IMFAttributes, ppsinkwriter: *mut IMFSinkWriter) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSourceReaderFromByteStream(pbytestream: IMFByteStream, pattributes: IMFAttributes, ppsourcereader: *mut IMFSourceReader) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSourceReaderFromMediaSource(pmediasource: IMFMediaSource, pattributes: IMFAttributes, ppsourcereader: *mut IMFSourceReader) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateSourceReaderFromURL(pwszurl: super::super::Foundation::PWSTR, pattributes: IMFAttributes, ppsourcereader: *mut IMFSourceReader) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSourceResolver(ppisourceresolver: *mut IMFSourceResolver) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateStandardQualityManager(ppqualitymanager: *mut IMFQualityManager) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateStreamDescriptor(dwstreamidentifier: u32, cmediatypes: u32, apmediatypes: *const IMFMediaType, ppdescriptor: *mut IMFStreamDescriptor) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_System_Com")]
    pub fn MFCreateStreamOnMFByteStream(pbytestream: IMFByteStream, ppstream: *mut super::super::System::Com::IStream) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateStreamOnMFByteStreamEx(pbytestream: IMFByteStream, riid: *const ::windows_sys::core::GUID, ppv: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateSystemTimeSource(ppsystemtimesource: *mut IMFPresentationTimeSource) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateTempFile(accessmode: MF_FILE_ACCESSMODE, openmode: MF_FILE_OPENMODE, fflags: MF_FILE_FLAGS, ppibytestream: *mut IMFByteStream) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateTopoLoader(ppobj: *mut IMFTopoLoader) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateTopology(pptopo: *mut IMFTopology) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateTopologyNode(nodetype: MF_TOPOLOGY_TYPE, ppnode: *mut IMFTopologyNode) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateTrackedSample(ppmfsample: *mut IMFTrackedSample) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateTranscodeProfile(pptranscodeprofile: *mut IMFTranscodeProfile) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateTranscodeSinkActivate(ppactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateTranscodeTopology(psrc: IMFMediaSource, pwszoutputfilepath: super::super::Foundation::PWSTR, pprofile: IMFTranscodeProfile, pptranscodetopo: *mut IMFTopology) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateTranscodeTopologyFromByteStream(psrc: IMFMediaSource, poutputstream: IMFByteStream, pprofile: IMFTranscodeProfile, pptranscodetopo: *mut IMFTopology) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateTransformActivate(ppactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateVideoMediaType(pvideoformat: *const MFVIDEOFORMAT, ppivideomediatype: *mut IMFVideoMediaType) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Graphics_Gdi")]
    pub fn MFCreateVideoMediaTypeFromBitMapInfoHeader(pbmihbitmapinfoheader: *const super::super::Graphics::Gdi::BITMAPINFOHEADER, dwpixelaspectratiox: u32, dwpixelaspectratioy: u32, interlacemode: MFVideoInterlaceMode, videoflags: u64, qwframespersecondnumerator: u64, qwframesperseconddenominator: u64, dwmaxbitrate: u32, ppivideomediatype: *mut IMFVideoMediaType) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Graphics_Gdi")]
    pub fn MFCreateVideoMediaTypeFromBitMapInfoHeaderEx(pbmihbitmapinfoheader: *const super::super::Graphics::Gdi::BITMAPINFOHEADER, cbbitmapinfoheader: u32, dwpixelaspectratiox: u32, dwpixelaspectratioy: u32, interlacemode: MFVideoInterlaceMode, videoflags: u64, dwframespersecondnumerator: u32, dwframesperseconddenominator: u32, dwmaxbitrate: u32, ppivideomediatype: *mut IMFVideoMediaType) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateVideoMediaTypeFromSubtype(pamsubtype: *const ::windows_sys::core::GUID, ppivideomediatype: *mut IMFVideoMediaType) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateVideoMixer(powner: ::windows_sys::core::IUnknown, riiddevice: *const ::windows_sys::core::GUID, riid: *const ::windows_sys::core::GUID, ppv: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateVideoMixerAndPresenter(pmixerowner: ::windows_sys::core::IUnknown, ppresenterowner: ::windows_sys::core::IUnknown, riidmixer: *const ::windows_sys::core::GUID, ppvvideomixer: *mut *mut ::core::ffi::c_void, riidpresenter: *const ::windows_sys::core::GUID, ppvvideopresenter: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateVideoPresenter(powner: ::windows_sys::core::IUnknown, riiddevice: *const ::windows_sys::core::GUID, riid: *const ::windows_sys::core::GUID, ppvideopresenter: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateVideoRenderer(riidrenderer: *const ::windows_sys::core::GUID, ppvideorenderer: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateVideoRendererActivate(hwndvideo: super::super::Foundation::HWND, ppactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateVideoSampleAllocator(riid: *const ::windows_sys::core::GUID, ppsampleallocator: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateVideoSampleAllocatorEx(riid: *const ::windows_sys::core::GUID, ppsampleallocator: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateVideoSampleFromSurface(punksurface: ::windows_sys::core::IUnknown, ppsample: *mut IMFSample) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFCreateVirtualCamera(r#type: __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0001, lifetime: __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0002, access: __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0003, friendlyname: super::super::Foundation::PWSTR, sourceid: super::super::Foundation::PWSTR, categories: *const ::windows_sys::core::GUID, categorycount: u32, virtualcamera: *mut IMFVirtualCamera) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateWAVEMediaSink(ptargetbytestream: IMFByteStream, paudiomediatype: IMFMediaType, ppmediasink: *mut IMFMediaSink) -> ::windows_sys::core::HRESULT;
    pub fn MFCreateWICBitmapBuffer(riid: *const ::windows_sys::core::GUID, punksurface: ::windows_sys::core::IUnknown, ppbuffer: *mut IMFMediaBuffer) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
    pub fn MFCreateWMAEncoderActivate(pmediatype: IMFMediaType, pencodingconfigurationproperties: super::super::UI::Shell::PropertiesSystem::IPropertyStore, ppactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
    pub fn MFCreateWMVEncoderActivate(pmediatype: IMFMediaType, pencodingconfigurationproperties: super::super::UI::Shell::PropertiesSystem::IPropertyStore, ppactivate: *mut IMFActivate) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Media_Audio")]
    pub fn MFCreateWaveFormatExFromMFMediaType(pmftype: IMFMediaType, ppwf: *mut *mut super::Audio::WAVEFORMATEX, pcbsize: *mut u32, flags: u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_System_Com")]
    pub fn MFDeserializeAttributesFromStream(pattr: IMFAttributes, dwoptions: u32, pstm: super::super::System::Com::IStream) -> ::windows_sys::core::HRESULT;
    pub fn MFDeserializePresentationDescriptor(cbdata: u32, pbdata: *const u8, pppd: *mut IMFPresentationDescriptor) -> ::windows_sys::core::HRESULT;
    pub fn MFEndCreateFile(presult: IMFAsyncResult, ppfile: *mut IMFByteStream) -> ::windows_sys::core::HRESULT;
    pub fn MFEndRegisterWorkQueueWithMMCSS(presult: IMFAsyncResult, pdwtaskid: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFEndUnregisterWorkQueueWithMMCSS(presult: IMFAsyncResult) -> ::windows_sys::core::HRESULT;
    pub fn MFEnumDeviceSources(pattributes: IMFAttributes, pppsourceactivate: *mut *mut IMFActivate, pcsourceactivate: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFFrameRateToAverageTimePerFrame(unnumerator: u32, undenominator: u32, punaveragetimeperframe: *mut u64) -> ::windows_sys::core::HRESULT;
    pub fn MFGetAttributesAsBlob(pattributes: IMFAttributes, pbuf: *mut u8, cbbufsize: u32) -> ::windows_sys::core::HRESULT;
    pub fn MFGetAttributesAsBlobSize(pattributes: IMFAttributes, pcbbufsize: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFGetContentProtectionSystemCLSID(guidprotectionsystemid: *const ::windows_sys::core::GUID, pclsid: *mut ::windows_sys::core::GUID) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFGetLocalId(verifier: *const u8, size: u32, id: *mut super::super::Foundation::PWSTR) -> ::windows_sys::core::HRESULT;
    pub fn MFGetMFTMerit(pmft: ::windows_sys::core::IUnknown, cbverifier: u32, verifier: *const u8, merit: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFGetPlaneSize(format: u32, dwwidth: u32, dwheight: u32, pdwplanesize: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFGetPluginControl(ppplugincontrol: *mut IMFPluginControl) -> ::windows_sys::core::HRESULT;
    pub fn MFGetService(punkobject: ::windows_sys::core::IUnknown, guidservice: *const ::windows_sys::core::GUID, riid: *const ::windows_sys::core::GUID, ppvobject: *mut *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
    pub fn MFGetStrideForBitmapInfoHeader(format: u32, dwwidth: u32, pstride: *mut i32) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_System_Com", feature = "Win32_System_Com_StructuredStorage"))]
    pub fn MFGetSupportedMimeTypes(ppropvarmimetypearray: *mut super::super::System::Com::StructuredStorage::PROPVARIANT) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_System_Com", feature = "Win32_System_Com_StructuredStorage"))]
    pub fn MFGetSupportedSchemes(ppropvarschemearray: *mut super::super::System::Com::StructuredStorage::PROPVARIANT) -> ::windows_sys::core::HRESULT;
    pub fn MFGetSystemId(ppid: *mut IMFSystemId) -> ::windows_sys::core::HRESULT;
    pub fn MFGetSystemTime() -> i64;
    pub fn MFGetTimerPeriodicity(periodicity: *mut u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFGetTopoNodeCurrentType(pnode: IMFTopologyNode, dwstreamindex: u32, foutput: super::super::Foundation::BOOL, pptype: *mut IMFMediaType) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFGetUncompressedVideoFormat(pvideoformat: *const MFVIDEOFORMAT) -> u32;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFGetWorkQueueMMCSSClass(dwworkqueueid: u32, pwszclass: super::super::Foundation::PWSTR, pcchclass: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFGetWorkQueueMMCSSPriority(dwworkqueueid: u32, lpriority: *mut i32) -> ::windows_sys::core::HRESULT;
    pub fn MFGetWorkQueueMMCSSTaskId(dwworkqueueid: u32, pdwtaskid: *mut u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFHeapAlloc(nsize: usize, dwflags: u32, pszfile: super::super::Foundation::PSTR, line: i32, eat: EAllocationType) -> *mut ::core::ffi::c_void;
    pub fn MFHeapFree(pv: *mut ::core::ffi::c_void);
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_Media_DirectShow"))]
    pub fn MFInitAMMediaTypeFromMFMediaType(pmftype: IMFMediaType, guidformatblocktype: ::windows_sys::core::GUID, pamtype: *mut super::DirectShow::AM_MEDIA_TYPE) -> ::windows_sys::core::HRESULT;
    pub fn MFInitAttributesFromBlob(pattributes: IMFAttributes, pbuf: *const u8, cbbufsize: u32) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_Media_DirectShow"))]
    pub fn MFInitMediaTypeFromAMMediaType(pmftype: IMFMediaType, pamtype: *const super::DirectShow::AM_MEDIA_TYPE) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFInitMediaTypeFromMFVideoFormat(pmftype: IMFMediaType, pmfvf: *const MFVIDEOFORMAT, cbbufsize: u32) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Gdi", feature = "Win32_Media_DirectShow"))]
    pub fn MFInitMediaTypeFromMPEG1VideoInfo(pmftype: IMFMediaType, pmp1vi: *const super::DirectShow::MPEG1VIDEOINFO, cbbufsize: u32, psubtype: *const ::windows_sys::core::GUID) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Gdi", feature = "Win32_Media_DirectShow"))]
    pub fn MFInitMediaTypeFromMPEG2VideoInfo(pmftype: IMFMediaType, pmp2vi: *const super::DirectShow::MPEG2VIDEOINFO, cbbufsize: u32, psubtype: *const ::windows_sys::core::GUID) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Gdi", feature = "Win32_Media_DirectShow"))]
    pub fn MFInitMediaTypeFromVideoInfoHeader(pmftype: IMFMediaType, pvih: *const super::DirectShow::VIDEOINFOHEADER, cbbufsize: u32, psubtype: *const ::windows_sys::core::GUID) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Gdi", feature = "Win32_Media_DirectShow"))]
    pub fn MFInitMediaTypeFromVideoInfoHeader2(pmftype: IMFMediaType, pvih2: *const super::DirectShow::VIDEOINFOHEADER2, cbbufsize: u32, psubtype: *const ::windows_sys::core::GUID) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Media_Audio")]
    pub fn MFInitMediaTypeFromWaveFormatEx(pmftype: IMFMediaType, pwaveformat: *const super::Audio::WAVEFORMATEX, cbbufsize: u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFInitVideoFormat(pvideoformat: *const MFVIDEOFORMAT, r#type: MFStandardVideoFormat) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFInitVideoFormat_RGB(pvideoformat: *const MFVIDEOFORMAT, dwwidth: u32, dwheight: u32, d3dfmt: u32) -> ::windows_sys::core::HRESULT;
    pub fn MFInvokeCallback(pasyncresult: IMFAsyncResult) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFIsContentProtectionDeviceSupported(protectionsystemid: *const ::windows_sys::core::GUID, issupported: *mut super::super::Foundation::BOOL) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFIsFormatYUV(format: u32) -> super::super::Foundation::BOOL;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFIsVirtualCameraTypeSupported(r#type: __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0001, supported: *mut super::super::Foundation::BOOL) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFLoadSignedLibrary(pszname: super::super::Foundation::PWSTR, pplib: *mut IMFSignedLibrary) -> ::windows_sys::core::HRESULT;
    pub fn MFLockDXGIDeviceManager(presettoken: *mut u32, ppmanager: *mut IMFDXGIDeviceManager) -> ::windows_sys::core::HRESULT;
    pub fn MFLockPlatform() -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFLockSharedWorkQueue(wszclass: super::super::Foundation::PWSTR, basepriority: i32, pdwtaskid: *mut u32, pid: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFLockWorkQueue(dwworkqueue: u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Graphics_Dxgi_Common")]
    pub fn MFMapDX9FormatToDXGIFormat(dx9: u32) -> super::super::Graphics::Dxgi::Common::DXGI_FORMAT;
    #[cfg(feature = "Win32_Graphics_Dxgi_Common")]
    pub fn MFMapDXGIFormatToDX9Format(dx11: super::super::Graphics::Dxgi::Common::DXGI_FORMAT) -> u32;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFPCreateMediaPlayer(pwszurl: super::super::Foundation::PWSTR, fstartplayback: super::super::Foundation::BOOL, creationoptions: MFP_CREATION_OPTIONS, pcallback: IMFPMediaPlayerCallback, hwnd: super::super::Foundation::HWND, ppmediaplayer: *mut IMFPMediaPlayer) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFPutWaitingWorkItem(hevent: super::super::Foundation::HANDLE, priority: i32, presult: IMFAsyncResult, pkey: *mut u64) -> ::windows_sys::core::HRESULT;
    pub fn MFPutWorkItem(dwqueue: u32, pcallback: IMFAsyncCallback, pstate: ::windows_sys::core::IUnknown) -> ::windows_sys::core::HRESULT;
    pub fn MFPutWorkItem2(dwqueue: u32, priority: i32, pcallback: IMFAsyncCallback, pstate: ::windows_sys::core::IUnknown) -> ::windows_sys::core::HRESULT;
    pub fn MFPutWorkItemEx(dwqueue: u32, presult: IMFAsyncResult) -> ::windows_sys::core::HRESULT;
    pub fn MFPutWorkItemEx2(dwqueue: u32, priority: i32, presult: IMFAsyncResult) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFRegisterLocalByteStreamHandler(szfileextension: super::super::Foundation::PWSTR, szmimetype: super::super::Foundation::PWSTR, pactivate: IMFActivate) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFRegisterLocalSchemeHandler(szscheme: super::super::Foundation::PWSTR, pactivate: IMFActivate) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFRegisterPlatformWithMMCSS(wszclass: super::super::Foundation::PWSTR, pdwtaskid: *mut u32, lpriority: i32) -> ::windows_sys::core::HRESULT;
    pub fn MFRemovePeriodicCallback(dwkey: u32) -> ::windows_sys::core::HRESULT;
    pub fn MFRequireProtectedEnvironment(ppresentationdescriptor: IMFPresentationDescriptor) -> ::windows_sys::core::HRESULT;
    pub fn MFScheduleWorkItem(pcallback: IMFAsyncCallback, pstate: ::windows_sys::core::IUnknown, timeout: i64, pkey: *mut u64) -> ::windows_sys::core::HRESULT;
    pub fn MFScheduleWorkItemEx(presult: IMFAsyncResult, timeout: i64, pkey: *mut u64) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_System_Com")]
    pub fn MFSerializeAttributesToStream(pattr: IMFAttributes, dwoptions: u32, pstm: super::super::System::Com::IStream) -> ::windows_sys::core::HRESULT;
    pub fn MFSerializePresentationDescriptor(ppd: IMFPresentationDescriptor, pcbdata: *mut u32, ppbdata: *mut *mut u8) -> ::windows_sys::core::HRESULT;
    pub fn MFShutdown() -> ::windows_sys::core::HRESULT;
    pub fn MFShutdownObject(punk: ::windows_sys::core::IUnknown) -> ::windows_sys::core::HRESULT;
    pub fn MFSplitSample(psample: IMFSample, poutputsamples: *mut IMFSample, dwoutputsamplemaxcount: u32, pdwoutputsamplecount: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFStartup(version: u32, dwflags: u32) -> ::windows_sys::core::HRESULT;
    pub fn MFTEnum(guidcategory: ::windows_sys::core::GUID, flags: u32, pinputtype: *const MFT_REGISTER_TYPE_INFO, poutputtype: *const MFT_REGISTER_TYPE_INFO, pattributes: IMFAttributes, ppclsidmft: *mut *mut ::windows_sys::core::GUID, pcmfts: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFTEnum2(guidcategory: ::windows_sys::core::GUID, flags: u32, pinputtype: *const MFT_REGISTER_TYPE_INFO, poutputtype: *const MFT_REGISTER_TYPE_INFO, pattributes: IMFAttributes, pppmftactivate: *mut *mut IMFActivate, pnummftactivate: *mut u32) -> ::windows_sys::core::HRESULT;
    pub fn MFTEnumEx(guidcategory: ::windows_sys::core::GUID, flags: u32, pinputtype: *const MFT_REGISTER_TYPE_INFO, poutputtype: *const MFT_REGISTER_TYPE_INFO, pppmftactivate: *mut *mut IMFActivate, pnummftactivate: *mut u32) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFTGetInfo(clsidmft: ::windows_sys::core::GUID, pszname: *mut super::super::Foundation::PWSTR, ppinputtypes: *mut *mut MFT_REGISTER_TYPE_INFO, pcinputtypes: *mut u32, ppoutputtypes: *mut *mut MFT_REGISTER_TYPE_INFO, pcoutputtypes: *mut u32, ppattributes: *mut IMFAttributes) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFTRegister(clsidmft: ::windows_sys::core::GUID, guidcategory: ::windows_sys::core::GUID, pszname: super::super::Foundation::PWSTR, flags: u32, cinputtypes: u32, pinputtypes: *const MFT_REGISTER_TYPE_INFO, coutputtypes: u32, poutputtypes: *const MFT_REGISTER_TYPE_INFO, pattributes: IMFAttributes) -> ::windows_sys::core::HRESULT;
    #[cfg(all(feature = "Win32_Foundation", feature = "Win32_System_Com"))]
    pub fn MFTRegisterLocal(pclassfactory: super::super::System::Com::IClassFactory, guidcategory: *const ::windows_sys::core::GUID, pszname: super::super::Foundation::PWSTR, flags: u32, cinputtypes: u32, pinputtypes: *const MFT_REGISTER_TYPE_INFO, coutputtypes: u32, poutputtypes: *const MFT_REGISTER_TYPE_INFO) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Foundation")]
    pub fn MFTRegisterLocalByCLSID(clisdmft: *const ::windows_sys::core::GUID, guidcategory: *const ::windows_sys::core::GUID, pszname: super::super::Foundation::PWSTR, flags: u32, cinputtypes: u32, pinputtypes: *const MFT_REGISTER_TYPE_INFO, coutputtypes: u32, poutputtypes: *const MFT_REGISTER_TYPE_INFO) -> ::windows_sys::core::HRESULT;
    pub fn MFTUnregister(clsidmft: ::windows_sys::core::GUID) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_System_Com")]
    pub fn MFTUnregisterLocal(pclassfactory: super::super::System::Com::IClassFactory) -> ::windows_sys::core::HRESULT;
    pub fn MFTUnregisterLocalByCLSID(clsidmft: ::windows_sys::core::GUID) -> ::windows_sys::core::HRESULT;
    pub fn MFTranscodeGetAudioOutputAvailableTypes(guidsubtype: *const ::windows_sys::core::GUID, dwmftflags: u32, pcodecconfig: IMFAttributes, ppavailabletypes: *mut IMFCollection) -> ::windows_sys::core::HRESULT;
    pub fn MFUnlockDXGIDeviceManager() -> ::windows_sys::core::HRESULT;
    pub fn MFUnlockPlatform() -> ::windows_sys::core::HRESULT;
    pub fn MFUnlockWorkQueue(dwworkqueue: u32) -> ::windows_sys::core::HRESULT;
    pub fn MFUnregisterPlatformFromMMCSS() -> ::windows_sys::core::HRESULT;
    pub fn MFUnwrapMediaType(pwrap: IMFMediaType, pporig: *mut IMFMediaType) -> ::windows_sys::core::HRESULT;
    pub fn MFValidateMediaTypeSize(formattype: ::windows_sys::core::GUID, pblock: *const u8, cbsize: u32) -> ::windows_sys::core::HRESULT;
    pub fn MFWrapMediaType(porig: IMFMediaType, majortype: *const ::windows_sys::core::GUID, subtype: *const ::windows_sys::core::GUID, ppwrap: *mut IMFMediaType) -> ::windows_sys::core::HRESULT;
    pub fn MFllMulDiv(a: i64, b: i64, c: i64, d: i64) -> i64;
    #[cfg(feature = "Win32_Foundation")]
    pub fn OPMGetVideoOutputForTarget(padapterluid: *const super::super::Foundation::LUID, vidpntarget: u32, vos: OPM_VIDEO_OUTPUT_SEMANTICS, ppopmvideooutput: *mut IOPMVideoOutput) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Graphics_Gdi")]
    pub fn OPMGetVideoOutputsFromHMONITOR(hmonitor: super::super::Graphics::Gdi::HMONITOR, vos: OPM_VIDEO_OUTPUT_SEMANTICS, pulnumvideooutputs: *mut u32, pppopmvideooutputarray: *mut *mut IOPMVideoOutput) -> ::windows_sys::core::HRESULT;
    #[cfg(feature = "Win32_Graphics_Direct3D9")]
    pub fn OPMGetVideoOutputsFromIDirect3DDevice9Object(pdirect3ddevice9: super::super::Graphics::Direct3D9::IDirect3DDevice9, vos: OPM_VIDEO_OUTPUT_SEMANTICS, pulnumvideooutputs: *mut u32, pppopmvideooutputarray: *mut *mut IOPMVideoOutput) -> ::windows_sys::core::HRESULT;
    pub fn OPMXboxEnableHDCP(hdcptype: OPM_HDCP_TYPE) -> ::windows_sys::core::HRESULT;
    pub fn OPMXboxGetHDCPStatus(phdcpstatus: *mut OPM_HDCP_STATUS) -> ::windows_sys::core::HRESULT;
    pub fn OPMXboxGetHDCPStatusAndType(phdcpstatus: *mut OPM_HDCP_STATUS, phdcptype: *mut OPM_HDCP_TYPE) -> ::windows_sys::core::HRESULT;
}
pub const AACMFTEncoder: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2477722705, data2: 8821, data3: 17874, data4: [163, 91, 242, 186, 33, 202, 237, 0] };
pub type AEC_INPUT_STREAM = i32;
pub const AEC_CAPTURE_STREAM: AEC_INPUT_STREAM = 0i32;
pub const AEC_REFERENCE_STREAM: AEC_INPUT_STREAM = 1i32;
pub const AEC_MAX_SYSTEM_MODES: u32 = 6u32;
pub type AEC_SYSTEM_MODE = i32;
pub const SINGLE_CHANNEL_AEC: AEC_SYSTEM_MODE = 0i32;
pub const ADAPTIVE_ARRAY_ONLY: AEC_SYSTEM_MODE = 1i32;
pub const OPTIBEAM_ARRAY_ONLY: AEC_SYSTEM_MODE = 2i32;
pub const ADAPTIVE_ARRAY_AND_AEC: AEC_SYSTEM_MODE = 3i32;
pub const OPTIBEAM_ARRAY_AND_AEC: AEC_SYSTEM_MODE = 4i32;
pub const SINGLE_CHANNEL_NSAGC: AEC_SYSTEM_MODE = 5i32;
pub const MODE_NOT_SET: AEC_SYSTEM_MODE = 6i32;
pub type AEC_VAD_MODE = i32;
pub const AEC_VAD_DISABLED: AEC_VAD_MODE = 0i32;
pub const AEC_VAD_NORMAL: AEC_VAD_MODE = 1i32;
pub const AEC_VAD_FOR_AGC: AEC_VAD_MODE = 2i32;
pub const AEC_VAD_FOR_SILENCE_SUPPRESSION: AEC_VAD_MODE = 3i32;
pub const ALawCodecWrapper: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 919301644, data2: 30913, data3: 17074, data4: [153, 67, 132, 98, 98, 243, 23, 134] };
pub const AM_MEDIA_TYPE_REPRESENTATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3806603986, data2: 4908, data3: 18718, data4: [162, 104, 60, 124, 45, 202, 24, 31] };
#[repr(C, packed(1))]
pub struct ASF_FLAT_PICTURE {
    pub bPictureType: u8,
    pub dwDataLen: u32,
}
impl ::core::marker::Copy for ASF_FLAT_PICTURE {}
impl ::core::clone::Clone for ASF_FLAT_PICTURE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C, packed(1))]
pub struct ASF_FLAT_SYNCHRONISED_LYRICS {
    pub bTimeStampFormat: u8,
    pub bContentType: u8,
    pub dwLyricsLen: u32,
}
impl ::core::marker::Copy for ASF_FLAT_SYNCHRONISED_LYRICS {}
impl ::core::clone::Clone for ASF_FLAT_SYNCHRONISED_LYRICS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct ASF_INDEX_DESCRIPTOR {
    pub Identifier: ASF_INDEX_IDENTIFIER,
    pub cPerEntryBytes: u16,
    pub szDescription: [u16; 32],
    pub dwInterval: u32,
}
impl ::core::marker::Copy for ASF_INDEX_DESCRIPTOR {}
impl ::core::clone::Clone for ASF_INDEX_DESCRIPTOR {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct ASF_INDEX_IDENTIFIER {
    pub guidIndexType: ::windows_sys::core::GUID,
    pub wStreamNumber: u16,
}
impl ::core::marker::Copy for ASF_INDEX_IDENTIFIER {}
impl ::core::clone::Clone for ASF_INDEX_IDENTIFIER {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct ASF_MUX_STATISTICS {
    pub cFramesWritten: u32,
    pub cFramesDropped: u32,
}
impl ::core::marker::Copy for ASF_MUX_STATISTICS {}
impl ::core::clone::Clone for ASF_MUX_STATISTICS {
    fn clone(&self) -> Self {
        *self
    }
}
pub type ASF_SELECTION_STATUS = i32;
pub const ASF_STATUS_NOTSELECTED: ASF_SELECTION_STATUS = 0i32;
pub const ASF_STATUS_CLEANPOINTSONLY: ASF_SELECTION_STATUS = 1i32;
pub const ASF_STATUS_ALLDATAUNITS: ASF_SELECTION_STATUS = 2i32;
pub type ASF_STATUSFLAGS = i32;
pub const ASF_STATUSFLAGS_INCOMPLETE: ASF_STATUSFLAGS = 1i32;
pub const ASF_STATUSFLAGS_NONFATAL_ERROR: ASF_STATUSFLAGS = 2i32;
pub const AVENC_H263V_LEVELCOUNT: u32 = 8u32;
pub const AVENC_H264V_LEVELCOUNT: u32 = 16u32;
pub const AVENC_H264V_MAX_MBBITS: u32 = 3200u32;
#[repr(C)]
pub struct AecQualityMetrics_Struct {
    pub i64Timestamp: i64,
    pub ConvergenceFlag: u8,
    pub MicClippedFlag: u8,
    pub MicSilenceFlag: u8,
    pub PstvFeadbackFlag: u8,
    pub SpkClippedFlag: u8,
    pub SpkMuteFlag: u8,
    pub GlitchFlag: u8,
    pub DoubleTalkFlag: u8,
    pub uGlitchCount: u32,
    pub uMicClipCount: u32,
    pub fDuration: f32,
    pub fTSVariance: f32,
    pub fTSDriftRate: f32,
    pub fVoiceLevel: f32,
    pub fNoiseLevel: f32,
    pub fERLE: f32,
    pub fAvgERLE: f32,
    pub dwReserved: u32,
}
impl ::core::marker::Copy for AecQualityMetrics_Struct {}
impl ::core::clone::Clone for AecQualityMetrics_Struct {
    fn clone(&self) -> Self {
        *self
    }
}
pub const CAC3DecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 64473090, data2: 60666, data3: 18393, data4: [178, 104, 95, 179, 227, 16, 222, 228] };
pub const CClusterDetectorDmo: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 921182404, data2: 5722, data3: 17697, data4: [134, 60, 97, 158, 17, 96, 212, 212] };
pub const CColorControlDmo: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2038454768,
    data2: 35274,
    data3: 16736,
    data4: [179, 37, 174, 180, 142, 254, 79, 154],
};
pub const CColorConvertDMO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2552431985, data2: 135, data3: 16900, data4: [176, 32, 50, 130, 83, 142, 87, 211] };
pub const CColorLegalizerDmo: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4261062483,
    data2: 58510,
    data3: 20019,
    data4: [156, 116, 152, 162, 127, 198, 114, 106],
};
pub const CDTVAudDecoderDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2384891954, data2: 65027, data3: 18259, data4: [155, 23, 24, 37, 60, 33, 114, 46] };
pub const CDTVVidDecoderDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1685552584,
    data2: 20004,
    data3: 19435,
    data4: [157, 25, 96, 163, 91, 225, 218, 175],
};
pub const CDVDecoderMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3846638021, data2: 7703, data3: 19597, data4: [148, 231, 71, 137, 64, 67, 53, 132] };
pub const CDVEncoderMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3358254889,
    data2: 49959,
    data3: 19662,
    data4: [145, 77, 129, 113, 254, 254, 190, 251],
};
pub const CDeColorConvMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1224952837,
    data2: 62524,
    data3: 16399,
    data4: [132, 193, 144, 166, 131, 25, 90, 58],
};
pub const CFrameInterpDMO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 175963675,
    data2: 27317,
    data3: 17204,
    data4: [158, 216, 63, 151, 203, 55, 218, 161],
};
pub const CFrameRateConvertDmo: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 32730338, data2: 2311, data3: 19851, data4: [151, 157, 241, 81, 190, 145, 200, 131] };
pub const CInterlaceMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3047726208,
    data2: 18689,
    data3: 16507,
    data4: [154, 188, 144, 217, 166, 68, 187, 70],
};
pub const CLSID_AudioResamplerMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4098340510,
    data2: 6276,
    data3: 19070,
    data4: [128, 85, 52, 111, 116, 214, 237, 179],
};
pub const CLSID_CAsfTocParser: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2608316658, data2: 34613, data3: 18117, data4: [185, 15, 95, 11, 48, 62, 246, 171] };
pub const CLSID_CAviTocParser: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 987555276, data2: 5064, data3: 17779, data4: [179, 40, 237, 67, 142, 182, 148, 249] };
pub const CLSID_CClusterDetectorEx: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1194673298,
    data2: 33406,
    data3: 19338,
    data4: [179, 24, 200, 14, 186, 19, 129, 240],
};
pub const CLSID_CFileClient: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3217871253, data2: 4676, data3: 18496, data4: [171, 68, 72, 9, 117, 196, 255, 228] };
pub const CLSID_CFileIo: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 295252373, data2: 4676, data3: 18496, data4: [171, 68, 72, 9, 117, 196, 255, 228] };
pub const CLSID_CToc: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1340228757,
    data2: 10446,
    data3: 18720,
    data4: [164, 196, 229, 86, 225, 240, 223, 42],
};
pub const CLSID_CTocCollection: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1347954989, data2: 41540, data3: 18496, data4: [171, 68, 72, 9, 117, 196, 255, 228] };
pub const CLSID_CTocEntry: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4063190533,
    data2: 22620,
    data3: 19951,
    data4: [133, 35, 101, 85, 207, 188, 12, 179],
};
pub const CLSID_CTocEntryList: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 982305980, data2: 3837, data3: 17315, data4: [184, 56, 243, 138, 85, 43, 162, 55] };
pub const CLSID_CTocParser: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1235136234, data2: 10039, data3: 18505, data4: [139, 182, 71, 241, 7, 234, 243, 88] };
pub const CLSID_CreateMediaExtensionObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4016416077, data2: 1928, data3: 17848, data4: [139, 20, 188, 15, 106, 107, 81, 55] };
pub const CLSID_FrameServerNetworkCameraSource: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2048998055,
    data2: 34415,
    data3: 16714,
    data4: [140, 26, 39, 92, 114, 131, 163, 149],
};
pub const CLSID_HttpSchemePlugin: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1154171947, data2: 40361, data3: 18911, data4: [179, 253, 2, 55, 119, 177, 110, 80] };
pub const CLSID_MFByteStreamProxyClassFactory: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1997442679,
    data2: 18710,
    data3: 17436,
    data4: [169, 167, 179, 66, 208, 238, 188, 113],
};
pub const CLSID_MFCaptureEngine: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4023269587,
    data2: 35092,
    data3: 18036,
    data4: [167, 223, 174, 27, 61, 101, 75, 138],
};
pub const CLSID_MFCaptureEngineClassFactory: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4023269587,
    data2: 35092,
    data3: 18036,
    data4: [167, 223, 174, 27, 61, 101, 75, 138],
};
pub const CLSID_MFImageSharingEngineClassFactory: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2989241145,
    data2: 34803,
    data3: 16473,
    data4: [160, 197, 3, 122, 169, 112, 126, 175],
};
pub const CLSID_MFMediaEngineClassFactory: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3024327386,
    data2: 18843,
    data3: 17515,
    data4: [164, 203, 0, 95, 234, 208, 230, 213],
};
pub const CLSID_MFMediaSharingEngineClassFactory: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4175628283,
    data2: 27973,
    data3: 19155,
    data4: [153, 147, 102, 205, 90, 82, 150, 89],
};
pub const CLSID_MFReadWriteClassFactory: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1222831375, data2: 39106, data3: 18999, data4: [190, 213, 22, 99, 18, 221, 216, 63] };
pub const CLSID_MFSinkWriter: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2747005719,
    data2: 33395,
    data3: 20050,
    data4: [158, 14, 151, 57, 220, 136, 121, 144],
};
pub const CLSID_MFSourceReader: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 393679676, data2: 2177, data3: 16667, data4: [165, 119, 173, 84, 95, 7, 20, 196] };
pub const CLSID_MFSourceResolver: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2431301135,
    data2: 58426,
    data3: 16776,
    data4: [188, 196, 228, 127, 223, 4, 134, 140],
};
pub const CLSID_MP3DecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3152980033,
    data2: 2659,
    data3: 20306,
    data4: [167, 171, 169, 179, 168, 78, 211, 138],
};
pub const CLSID_MPEG2ByteStreamPlugin: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1082596441,
    data2: 43840,
    data3: 18207,
    data4: [141, 195, 31, 37, 157, 134, 36, 121],
};
pub const CLSID_MPEG2DLNASink: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4200589253, data2: 27165, data3: 19217, data4: [180, 31, 249, 89, 214, 199, 101, 0] };
pub const CLSID_MSAACDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 852592295, data2: 8591, data3: 19573, data4: [136, 118, 221, 119, 39, 58, 137, 153] };
pub const CLSID_MSDDPlusDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 394005246, data2: 36875, data3: 18644, data4: [158, 76, 87, 173, 210, 80, 179, 212] };
pub const CLSID_MSH264DecoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1657699954, data2: 19569, data3: 19744, data4: [177, 93, 69, 40, 49, 168, 125, 157] };
pub const CLSID_MSH264EncoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1822753604, data2: 1306, data3: 19949, data4: [151, 121, 164, 51, 5, 22, 94, 53] };
pub const CLSID_MSH265DecoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1107972515, data2: 54789, data3: 17164, data4: [180, 252, 69, 39, 79, 166, 197, 98] };
pub const CLSID_MSMPEGAudDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1886419769,
    data2: 45770,
    data3: 16405,
    data4: [171, 234, 248, 68, 125, 34, 216, 139],
};
pub const CLSID_MSMPEGDecoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 762355282,
    data2: 4671,
    data3: 18869,
    data4: [156, 188, 154, 245, 205, 226, 143, 185],
};
pub const CLSID_MSOpusDecoder: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1675721744,
    data2: 11587,
    data3: 19522,
    data4: [143, 227, 141, 139, 99, 228, 106, 106],
};
pub const CLSID_MSVPxDecoder: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3819631944, data2: 51620, data3: 19566, data4: [35, 77, 90, 218, 55, 75, 0, 0] };
pub const CLSID_NetSchemePlugin: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3925142443,
    data2: 55675,
    data3: 17982,
    data4: [162, 177, 197, 78, 227, 249, 65, 77],
};
pub const CLSID_PlayToSourceClassFactory: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3658961818, data2: 15811, data3: 17089, data4: [167, 73, 161, 131, 181, 31, 8, 94] };
pub const CLSID_UrlmonSchemePlugin: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2663691513,
    data2: 12329,
    data3: 17837,
    data4: [148, 123, 52, 77, 226, 162, 73, 226],
};
pub const CLSID_VideoProcessorMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2289384230,
    data2: 23332,
    data3: 18877,
    data4: [178, 231, 12, 68, 92, 120, 201, 130],
};
pub const CLSID_WMADecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 787172063, data2: 17784, data3: 19728, data4: [188, 167, 187, 149, 95, 86, 50, 10] };
pub const CLSID_WMDRMSystemID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2303245090, data2: 4541, data3: 18326, data4: [147, 227, 151, 77, 27, 87, 86, 120] };
pub const CLSID_WMVDecoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2194887647,
    data2: 37053,
    data3: 17282,
    data4: [139, 194, 63, 97, 146, 183, 110, 52],
};
pub const CMP3DecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3152980033,
    data2: 2659,
    data3: 20306,
    data4: [167, 171, 169, 179, 168, 78, 211, 138],
};
pub const CMPEG2AudDecoderDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3790708920,
    data2: 48878,
    data3: 18701,
    data4: [186, 124, 6, 108, 64, 181, 226, 185],
};
pub const CMPEG2AudioEncoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1185209692,
    data2: 29688,
    data3: 17156,
    data4: [148, 223, 48, 143, 118, 9, 116, 244],
};
pub const CMPEG2EncoderAudioDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2899596220,
    data2: 50570,
    data3: 17617,
    data4: [187, 245, 191, 179, 37, 190, 45, 120],
};
pub const CMPEG2EncoderDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1599799114,
    data2: 12159,
    data3: 17017,
    data4: [136, 194, 205, 136, 235, 57, 209, 68],
};
pub const CMPEG2EncoderVideoDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1108675801, data2: 51866, data3: 20133, data4: [153, 57, 48, 238, 3, 127, 110, 116] };
pub const CMPEG2VidDecoderDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 556175611,
    data2: 33765,
    data3: 17702,
    data4: [143, 215, 116, 71, 139, 121, 57, 205],
};
pub const CMPEG2VideoEncoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3862126338,
    data2: 32951,
    data3: 19908,
    data4: [173, 250, 223, 231, 33, 13, 32, 213],
};
pub const CMPEGAACDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2380142450,
    data2: 60845,
    data3: 16835,
    data4: [180, 190, 31, 48, 251, 78, 224, 214],
};
pub const CMSAACDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 852592295, data2: 8591, data3: 19573, data4: [136, 118, 221, 119, 39, 58, 137, 153] };
pub const CMSAC3Enc: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3333685474,
    data2: 8359,
    data3: 20056,
    data4: [162, 254, 36, 97, 150, 130, 206, 108],
};
pub const CMSALACDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3234692370, data2: 12796, data3: 19388, data4: [179, 99, 115, 34, 238, 62, 24, 121] };
pub const CMSALACEncMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2595660428,
    data2: 29838,
    data3: 19306,
    data4: [191, 255, 204, 68, 59, 142, 143, 180],
};
pub const CMSDDPlusDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 394005246, data2: 36875, data3: 18644, data4: [158, 76, 87, 173, 210, 80, 179, 212] };
pub const CMSDolbyDigitalEncMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2889029065,
    data2: 62593,
    data3: 17879,
    data4: [130, 108, 11, 64, 108, 31, 100, 184],
};
pub const CMSFLACDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1795898987,
    data2: 41669,
    data3: 17684,
    data4: [128, 85, 175, 232, 169, 82, 66, 217],
};
pub const CMSFLACEncMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 310708713,
    data2: 50254,
    data3: 17884,
    data4: [149, 233, 194, 85, 184, 244, 102, 166],
};
pub const CMSH263EncoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3158834430, data2: 39072, data3: 20263, data4: [187, 7, 105, 138, 242, 79, 43, 56] };
pub const CMSH264DecoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1657699954, data2: 19569, data3: 19744, data4: [177, 93, 69, 40, 49, 168, 125, 157] };
pub const CMSH264EncoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1822753604, data2: 1306, data3: 19949, data4: [151, 121, 164, 51, 5, 22, 94, 53] };
pub const CMSH264RemuxMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 94666427, data2: 35824, data3: 19647, data4: [173, 47, 59, 113, 215, 88, 102, 245] };
pub const CMSH265EncoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4076355700,
    data2: 35786,
    data3: 16573,
    data4: [145, 89, 232, 128, 246, 115, 221, 59],
};
pub const CMSMPEGAudDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1886419769,
    data2: 45770,
    data3: 16405,
    data4: [171, 234, 248, 68, 125, 34, 216, 139],
};
pub const CMSMPEGDecoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 762355282,
    data2: 4671,
    data3: 18869,
    data4: [156, 188, 154, 245, 205, 226, 143, 185],
};
pub const CMSOpusDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1675721744,
    data2: 11587,
    data3: 19522,
    data4: [143, 227, 141, 139, 99, 228, 106, 106],
};
pub const CMSSCDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2075112369, data2: 55540, data3: 17017, data4: [146, 83, 39, 218, 66, 49, 8, 222] };
pub const CMSSCEncMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2360986630,
    data2: 53561,
    data3: 19174,
    data4: [139, 180, 65, 230, 18, 225, 65, 213],
};
pub const CMSSCEncMediaObject2: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4160741536,
    data2: 42229,
    data3: 17589,
    data4: [148, 158, 21, 237, 43, 198, 111, 157],
};
pub const CMSVPXEncoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2931214165,
    data2: 9542,
    data3: 18561,
    data4: [130, 204, 225, 90, 229, 235, 255, 61],
};
pub const CMSVideoDSPMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1364662084, data2: 32740, data3: 20466, data4: [164, 152, 45, 195, 79, 247, 79, 27] };
pub const CMpeg2DecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2252170957,
    data2: 52686,
    data3: 17943,
    data4: [180, 127, 200, 146, 156, 252, 40, 166],
};
pub const CMpeg43DecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3416909707,
    data2: 18851,
    data3: 18922,
    data4: [147, 212, 107, 203, 168, 196, 222, 7],
};
pub const CMpeg4DecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4084298378, data2: 24658, data3: 19783, data4: [130, 124, 208, 57, 51, 93, 254, 10] };
pub const CMpeg4EncMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 619862232,
    data2: 50769,
    data3: 16450,
    data4: [147, 228, 202, 101, 74, 187, 104, 44],
};
pub const CMpeg4sDecMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1451663577,
    data2: 65081,
    data3: 16543,
    data4: [157, 255, 63, 219, 200, 73, 249, 245],
};
pub const CMpeg4sDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 705805026,
    data2: 65134,
    data3: 16969,
    data4: [134, 75, 158, 158, 214, 232, 219, 194],
};
pub const CMpeg4sEncMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1858447294,
    data2: 55326,
    data3: 20382,
    data4: [173, 163, 205, 27, 242, 98, 182, 216],
};
pub const CNokiaAACCCDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3938417263,
    data2: 52410,
    data3: 19808,
    data4: [134, 32, 177, 82, 204, 151, 114, 99],
};
pub const CNokiaAACDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018346980, data2: 20009, data3: 19524, data4: [167, 62, 45, 124, 44, 70, 214, 236] };
pub const CODECAPI_AVAudioChannelConfig: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 402169011, data2: 50061, data3: 17256, data4: [158, 222, 99, 185, 77, 23, 127, 159] };
pub const CODECAPI_AVAudioChannelCount: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 490046404, data2: 5507, data3: 18254, data4: [183, 26, 94, 228, 99, 193, 152, 228] };
pub const CODECAPI_AVAudioSampleRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2535270179, data2: 6859, data3: 17127, data4: [133, 92, 82, 10, 75, 112, 165, 242] };
pub const CODECAPI_AVDDSurroundMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2582836102,
    data2: 39121,
    data3: 17490,
    data4: [161, 99, 171, 199, 138, 110, 183, 112],
};
pub const CODECAPI_AVDSPLoudnessEqualization: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2331843093, data2: 6162, data3: 19647, data4: [147, 25, 67, 58, 91, 42, 59, 39] };
pub const CODECAPI_AVDSPSpeakerFill: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1444068513,
    data2: 22234,
    data3: 17794,
    data4: [141, 161, 202, 128, 144, 249, 39, 104],
};
pub const CODECAPI_AVDecAACDownmixMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 19350645, data2: 63163, data3: 16407, data4: [176, 132, 129, 167, 99, 201, 66, 212] };
pub const CODECAPI_AVDecAudioDualMono: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1246940584, data2: 12536, data3: 16918, data4: [190, 15, 186, 11, 32, 37, 146, 29] };
pub const CODECAPI_AVDecAudioDualMonoReproMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2769314182,
    data2: 52372,
    data3: 19401,
    data4: [140, 217, 170, 47, 97, 246, 128, 126],
};
pub const CODECAPI_AVDecCommonInputFormat: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3842003513,
    data2: 48521,
    data3: 19427,
    data4: [156, 15, 93, 222, 49, 121, 136, 204],
};
pub const CODECAPI_AVDecCommonMeanBitRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1497924119, data2: 122, data3: 20346, data4: [142, 65, 92, 72, 177, 234, 197, 198] };
pub const CODECAPI_AVDecCommonMeanBitRateInterval: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 249837510, data2: 14503, data3: 19548, data4: [148, 76, 104, 171, 66, 17, 107, 133] };
pub const CODECAPI_AVDecCommonOutputFormat: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1014562856,
    data2: 49358,
    data3: 16982,
    data4: [177, 162, 27, 15, 200, 177, 220, 220],
};
pub const CODECAPI_AVDecDDDynamicRangeScaleHigh: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1343843361,
    data2: 7987,
    data3: 19189,
    data4: [178, 150, 17, 66, 109, 108, 135, 137],
};
pub const CODECAPI_AVDecDDDynamicRangeScaleLow: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 72245988, data2: 4517, data3: 17109, data4: [163, 178, 59, 178, 199, 194, 215, 207] };
pub const CODECAPI_AVDecDDMatrixDecodingMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3720876453, data2: 1261, data3: 19443, data4: [160, 202, 208, 4, 73, 249, 53, 95] };
pub const CODECAPI_AVDecDDOperationalMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3604399825,
    data2: 1614,
    data3: 20445,
    data4: [164, 14, 62, 203, 252, 183, 235, 208],
};
pub const CODECAPI_AVDecDDStereoDownMixMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1826886188,
    data2: 16105,
    data3: 16770,
    data4: [180, 174, 193, 15, 192, 136, 100, 157],
};
pub const CODECAPI_AVDecDisableVideoPostProcessing: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4168389011,
    data2: 26234,
    data3: 20268,
    data4: [169, 232, 93, 74, 249, 36, 240, 143],
};
pub const CODECAPI_AVDecHEAACDynamicRangeControl: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 679250622,
    data2: 27044,
    data3: 19769,
    data4: [128, 128, 211, 217, 113, 33, 120, 160],
};
pub const CODECAPI_AVDecNumWorkerThreads: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2506212328,
    data2: 60062,
    data3: 17461,
    data4: [155, 30, 169, 62, 105, 24, 148, 216],
};
pub const CODECAPI_AVDecSoftwareDynamicFormatChange: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2251173642, data2: 20603, data3: 18431, data4: [175, 71, 1, 226, 98, 66, 152, 183] };
pub const CODECAPI_AVDecVideoAcceleration_H264: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4158360111,
    data2: 20296,
    data3: 20200,
    data4: [174, 49, 139, 110, 190, 85, 138, 226],
};
pub const CODECAPI_AVDecVideoAcceleration_MPEG2: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4158360110,
    data2: 20296,
    data3: 20200,
    data4: [174, 49, 139, 110, 190, 85, 138, 226],
};
pub const CODECAPI_AVDecVideoAcceleration_VC1: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4158360112,
    data2: 20296,
    data3: 20200,
    data4: [174, 49, 139, 110, 190, 85, 138, 226],
};
pub const CODECAPI_AVDecVideoCodecType: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1128605925,
    data2: 8688,
    data3: 18102,
    data4: [182, 44, 155, 27, 107, 101, 140, 209],
};
pub const CODECAPI_AVDecVideoDXVABusEncryption: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1108688011,
    data2: 64779,
    data3: 18277,
    data4: [164, 98, 221, 217, 232, 188, 195, 136],
};
pub const CODECAPI_AVDecVideoDXVAMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4149801118,
    data2: 29495,
    data3: 19175,
    data4: [131, 135, 115, 220, 45, 84, 230, 125],
};
pub const CODECAPI_AVDecVideoDropPicWithMissingRef: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4163003267, data2: 5314, data3: 17767, data4: [151, 52, 80, 4, 233, 111, 248, 135] };
pub const CODECAPI_AVDecVideoFastDecodeMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1800576893,
    data2: 54193,
    data3: 18886,
    data4: [169, 153, 158, 198, 145, 27, 237, 191],
};
pub const CODECAPI_AVDecVideoH264ErrorConcealment: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3974933736,
    data2: 13366,
    data3: 17964,
    data4: [146, 148, 205, 123, 172, 215, 88, 169],
};
pub const CODECAPI_AVDecVideoImageSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1592095868,
    data2: 26625,
    data3: 19627,
    data4: [170, 241, 98, 72, 250, 132, 27, 164],
};
pub const CODECAPI_AVDecVideoInputScanType: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 944209439, data2: 3751, data3: 17101, data4: [140, 209, 19, 12, 237, 87, 197, 128] };
pub const CODECAPI_AVDecVideoMPEG2ErrorConcealment: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2636906008,
    data2: 29325,
    data3: 18642,
    data4: [179, 88, 188, 126, 67, 108, 102, 116],
};
pub const CODECAPI_AVDecVideoMaxCodedHeight: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1919066474,
    data2: 53980,
    data3: 20085,
    data4: [155, 168, 101, 192, 198, 211, 43, 19],
};
pub const CODECAPI_AVDecVideoMaxCodedWidth: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1524979640,
    data2: 30639,
    data3: 16885,
    data4: [159, 166, 77, 178, 254, 29, 75, 202],
};
pub const CODECAPI_AVDecVideoPixelAspectRatio: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2966389317, data2: 62253, data3: 16863, data4: [176, 44, 135, 189, 48, 77, 18, 171] };
pub const CODECAPI_AVDecVideoProcDeinterlaceCSC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4158360113,
    data2: 20296,
    data3: 20200,
    data4: [174, 49, 139, 110, 190, 85, 138, 226],
};
pub const CODECAPI_AVDecVideoSWPowerLevel: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4217185095,
    data2: 19928,
    data3: 17673,
    data4: [174, 208, 219, 95, 169, 170, 147, 244],
};
pub const CODECAPI_AVDecVideoSoftwareDeinterlaceMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 201904590, data2: 40173, data3: 17728, data4: [186, 227, 206, 179, 128, 20, 17, 9] };
pub const CODECAPI_AVDecVideoThumbnailGenerationMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 788369134,
    data2: 4432,
    data3: 17192,
    data4: [156, 245, 102, 220, 233, 51, 252, 244],
};
pub const CODECAPI_AVEnableInLoopDeblockFilter: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3538477977, data2: 1571, data3: 19443, data4: [146, 168, 77, 24, 24, 82, 157, 237] };
pub const CODECAPI_AVEncAdaptiveMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1142534533, data2: 55839, data3: 20307, data4: [188, 118, 9, 125, 12, 30, 251, 30] };
pub const CODECAPI_AVEncAudioDualMono: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 910692971, data2: 41960, data3: 17193, data4: [155, 58, 92, 229, 102, 164, 59, 211] };
pub const CODECAPI_AVEncAudioInputContent: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1042443307,
    data2: 24761,
    data3: 19001,
    data4: [176, 11, 167, 180, 15, 112, 213, 102],
};
pub const CODECAPI_AVEncAudioIntervalToEncode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2255375181, data2: 29274, data3: 18044, data4: [187, 1, 180, 150, 178, 59, 37, 249] };
pub const CODECAPI_AVEncAudioIntervalToSkip: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2294374292,
    data2: 50060,
    data3: 18326,
    data4: [169, 232, 150, 233, 103, 152, 63, 38],
};
pub const CODECAPI_AVEncAudioMapDestChannel0: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214368, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214369, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel10: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214378, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel11: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214379, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel12: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214380, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel13: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214381, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel14: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214382, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel15: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214383, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214370, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel3: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214371, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel4: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214372, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel5: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214373, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel6: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214374, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel7: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214375, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel8: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214376, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMapDestChannel9: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3160214377, data2: 57194, data3: 19990, data4: [152, 3, 184, 32, 7, 163, 12, 141] };
pub const CODECAPI_AVEncAudioMeanBitRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2450691515,
    data2: 20426,
    data3: 18041,
    data4: [170, 184, 158, 42, 29, 117, 51, 132],
};
pub const CODECAPI_AVEncChromaEncodeMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2319952730, data2: 18328, data3: 19603, data4: [181, 165, 85, 79, 154, 59, 159, 80] };
pub const CODECAPI_AVEncChromaUpdateTime: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1263524248, data2: 17012, data3: 16571, data4: [142, 228, 7, 85, 62, 126, 45, 58] };
pub const CODECAPI_AVEncCodecType: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 145705665,
    data2: 62450,
    data3: 19572,
    data4: [157, 207, 55, 242, 236, 121, 248, 38],
};
pub const CODECAPI_AVEncCommonAllowFrameDrops: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3628563915, data2: 38296, data3: 18659, data4: [141, 12, 117, 43, 242, 6, 9, 62] };
pub const CODECAPI_AVEncCommonBufferInLevel: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3653617883,
    data2: 64628,
    data3: 16484,
    data4: [148, 233, 205, 25, 249, 71, 237, 69],
};
pub const CODECAPI_AVEncCommonBufferOutLevel: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3433987913, data2: 53436, data3: 20029, data4: [165, 126, 251, 87, 64, 20, 0, 105] };
pub const CODECAPI_AVEncCommonBufferSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 230253940, data2: 46756, data3: 19595, data4: [129, 6, 55, 115, 222, 3, 16, 205] };
pub const CODECAPI_AVEncCommonFormatConstraint: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1472969144, data2: 4463, data3: 18769, data4: [180, 12, 194, 160, 53, 237, 143, 23] };
pub const CODECAPI_AVEncCommonLowLatency: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2638138709,
    data2: 35304,
    data3: 18698,
    data4: [151, 10, 12, 149, 72, 213, 165, 110],
};
pub const CODECAPI_AVEncCommonMaxBitRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2521950948,
    data2: 14777,
    data3: 20159,
    data4: [133, 239, 215, 244, 68, 236, 116, 101],
};
pub const CODECAPI_AVEncCommonMeanBitRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4146209652, data2: 8516, data3: 18453, data4: [181, 80, 163, 127, 142, 18, 238, 82] };
pub const CODECAPI_AVEncCommonMeanBitRateInterval: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3215601420, data2: 52098, data3: 19392, data4: [132, 116, 240, 106, 138, 13, 2, 88] };
pub const CODECAPI_AVEncCommonMinBitRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 269747634, data2: 8323, data3: 16436, data4: [168, 6, 239, 190, 221, 215, 201, 255] };
pub const CODECAPI_AVEncCommonMultipassMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 575880524,
    data2: 18401,
    data3: 16821,
    data4: [147, 82, 162, 183, 120, 14, 122, 196],
};
pub const CODECAPI_AVEncCommonPassEnd: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 238879164, data2: 51292, data3: 18045, data4: [139, 96, 196, 16, 18, 238, 59, 246] };
pub const CODECAPI_AVEncCommonPassStart: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1785164703,
    data2: 20149,
    data3: 17285,
    data4: [153, 40, 242, 118, 169, 57, 239, 149],
};
pub const CODECAPI_AVEncCommonQuality: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4240398243,
    data2: 32421,
    data3: 19212,
    data4: [150, 68, 105, 180, 12, 57, 195, 145],
};
pub const CODECAPI_AVEncCommonQualityVsSpeed: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2553490936, data2: 973, data3: 18283, data4: [137, 250, 63, 158, 68, 45, 236, 159] };
pub const CODECAPI_AVEncCommonRateControlMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 470157545, data2: 14092, data3: 18192, data4: [138, 88, 203, 97, 129, 196, 36, 35] };
pub const CODECAPI_AVEncCommonRealTime: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 339349494,
    data2: 41265,
    data3: 17370,
    data4: [184, 30, 152, 251, 184, 236, 55, 142],
};
pub const CODECAPI_AVEncCommonStreamEndHandling: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1789735087,
    data2: 27560,
    data3: 19660,
    data4: [143, 202, 24, 209, 155, 234, 235, 28],
};
pub const CODECAPI_AVEncCommonTranscodeEncodingProfile: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1766291580,
    data2: 62728,
    data3: 20137,
    data4: [177, 233, 161, 254, 58, 73, 251, 201],
};
pub const CODECAPI_AVEncDDAtoDConverterType: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1906284050, data2: 33185, data3: 18400, data4: [154, 5, 217, 74, 213, 252, 169, 72] };
pub const CODECAPI_AVEncDDCentreDownMixLevel: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3800368940,
    data2: 51544,
    data3: 19073,
    data4: [175, 210, 229, 224, 218, 241, 177, 72],
};
pub const CODECAPI_AVEncDDChannelBWLowPassFilter: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3784802845, data2: 53991, data3: 17378, data4: [173, 44, 0, 88, 47, 81, 133, 69] };
pub const CODECAPI_AVEncDDCopyright: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2257907830,
    data2: 52597,
    data3: 18461,
    data4: [165, 198, 169, 4, 220, 200, 40, 240],
};
pub const CODECAPI_AVEncDDDCHighPassFilter: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2506433439,
    data2: 34332,
    data3: 19144,
    data4: [191, 218, 224, 12, 180, 219, 133, 72],
};
pub const CODECAPI_AVEncDDDialogNormalization: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3607452367, data2: 61733, data3: 17277, data4: [167, 4, 121, 199, 159, 4, 4, 168] };
pub const CODECAPI_AVEncDDDigitalDeemphasis: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3760497346, data2: 38012, data3: 17836, data4: [135, 216, 241, 3, 12, 92, 0, 130] };
pub const CODECAPI_AVEncDDDynamicRangeCompressionControl: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3485663085,
    data2: 31160,
    data3: 19341,
    data4: [168, 170, 160, 201, 189, 28, 41, 64],
};
pub const CODECAPI_AVEncDDHeadphoneMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1079172076, data2: 21237, data3: 17141, data4: [155, 0, 209, 52, 177, 52, 27, 157] };
pub const CODECAPI_AVEncDDLFELowPassFilter: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3552055151, data2: 40213, data3: 17893, data4: [145, 190, 1, 156, 63, 171, 31, 1] };
pub const CODECAPI_AVEncDDLoRoCenterMixLvl_x10: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 486253090, data2: 9651, data3: 19444, data4: [155, 253, 231, 17, 18, 103, 133, 140] };
pub const CODECAPI_AVEncDDLoRoSurroundMixLvl_x10: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3878014966, data2: 60246, data3: 16583, data4: [132, 80, 43, 147, 103, 233, 21, 85] };
pub const CODECAPI_AVEncDDLtRtCenterMixLvl_x10: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3701549218,
    data2: 18719,
    data3: 17920,
    data4: [178, 218, 118, 227, 52, 75, 65, 151],
};
pub const CODECAPI_AVEncDDLtRtSurroundMixLvl_x10: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 555894471, data2: 15660, data3: 19962, data4: [188, 33, 101, 42, 144, 152, 105, 13] };
pub const CODECAPI_AVEncDDOriginalBitstream: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2523588608, data2: 23507, data3: 20473, data4: [149, 185, 211, 5, 102, 39, 56, 86] };
pub const CODECAPI_AVEncDDPreferredStereoDownMixMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2135845681,
    data2: 37253,
    data3: 16445,
    data4: [176, 162, 118, 55, 67, 230, 240, 99],
};
pub const CODECAPI_AVEncDDProductionInfoExists: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2964848223,
    data2: 46763,
    data3: 20288,
    data4: [150, 77, 141, 145, 241, 124, 25, 232],
};
pub const CODECAPI_AVEncDDProductionMixLevel: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 807211066, data2: 52217, data3: 18294, data4: [136, 153, 124, 21, 180, 97, 171, 38] };
pub const CODECAPI_AVEncDDProductionRoomType: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3671567712,
    data2: 9176,
    data3: 19127,
    data4: [162, 132, 85, 105, 134, 216, 166, 254],
};
pub const CODECAPI_AVEncDDRFPreEmphasisFilter: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 565134528, data2: 9294, data3: 20285, data4: [162, 204, 61, 48, 104, 178, 231, 63] };
pub const CODECAPI_AVEncDDService: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3538009799,
    data2: 20850,
    data3: 19754,
    data4: [165, 14, 47, 59, 130, 177, 221, 248],
};
pub const CODECAPI_AVEncDDSurround3dBAttenuation: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1296284061, data2: 12770, data3: 18617, data4: [191, 46, 92, 191, 26, 87, 39, 132] };
pub const CODECAPI_AVEncDDSurround90DegreeePhaseShift: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 636284061, data2: 13651, data3: 17088, data4: [187, 86, 210, 87, 146, 16, 79, 128] };
pub const CODECAPI_AVEncDDSurroundDownMixLevel: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2065749733, data2: 3023, data3: 17011, data4: [164, 135, 80, 107, 4, 121, 151, 233] };
pub const CODECAPI_AVEncDDSurroundExMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2439019758,
    data2: 56285,
    data3: 20150,
    data4: [188, 162, 170, 223, 175, 163, 221, 104],
};
pub const CODECAPI_AVEncEnableVideoProcessing: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 7293942, data2: 3747, data3: 19778, data4: [135, 2, 181, 216, 190, 15, 122, 146] };
pub const CODECAPI_AVEncH264CABACEnable: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4000099682,
    data2: 54021,
    data3: 16968,
    data4: [165, 14, 225, 178, 85, 247, 202, 248],
};
pub const CODECAPI_AVEncH264PPSID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3219300034, data2: 1388, data3: 19816, data4: [163, 141, 174, 89, 68, 200, 88, 46] };
pub const CODECAPI_AVEncH264SPSID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1358139217, data2: 11129, data3: 16611, data4: [179, 156, 126, 159, 160, 119, 5, 1] };
pub const CODECAPI_AVEncInputVideoSystem: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3202225261,
    data2: 46614,
    data3: 19911,
    data4: [146, 178, 245, 217, 250, 146, 152, 247],
};
pub const CODECAPI_AVEncLowPowerEncoder: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3060323714, data2: 35757, data3: 20330, data4: [145, 65, 55, 90, 149, 53, 139, 109] };
pub const CODECAPI_AVEncMP12MuxDVDNavPacks: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3344989421,
    data2: 36081,
    data3: 19097,
    data4: [131, 161, 238, 84, 97, 190, 53, 116],
};
pub const CODECAPI_AVEncMP12MuxEarliestPTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 359805622, data2: 63497, data3: 18254, data4: [148, 100, 167, 249, 48, 20, 168, 23] };
pub const CODECAPI_AVEncMP12MuxInitialSCR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 875801889, data2: 7057, data3: 18955, data4: [177, 144, 43, 119, 6, 59, 99, 164] };
pub const CODECAPI_AVEncMP12MuxLargestPacketSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 902739729, data2: 62561, data3: 19346, data4: [164, 239, 23, 182, 132, 30, 210, 84] };
pub const CODECAPI_AVEncMP12MuxMuxRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3993271410,
    data2: 19419,
    data3: 19101,
    data4: [142, 33, 65, 146, 108, 130, 61, 167],
};
pub const CODECAPI_AVEncMP12MuxNumStreams: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4145433153,
    data2: 56557,
    data3: 18009,
    data4: [168, 242, 251, 105, 63, 42, 76, 208],
};
pub const CODECAPI_AVEncMP12MuxPackSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4178969914, data2: 7400, data3: 20399, data4: [170, 11, 186, 49, 200, 0, 52, 184] };
pub const CODECAPI_AVEncMP12MuxPacketOverhead: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3825981216,
    data2: 14677,
    data3: 17491,
    data4: [172, 249, 183, 145, 50, 163, 143, 160],
};
pub const CODECAPI_AVEncMP12MuxSysAudioLock: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 263935826, data2: 7491, data3: 18367, data4: [189, 121, 242, 41, 61, 140, 227, 55] };
pub const CODECAPI_AVEncMP12MuxSysCSPS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2035482437,
    data2: 39949,
    data3: 18466,
    data4: [188, 130, 138, 215, 114, 224, 41, 147],
};
pub const CODECAPI_AVEncMP12MuxSysFixed: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3472595070,
    data2: 35151,
    data3: 17710,
    data4: [143, 137, 164, 239, 140, 236, 6, 58],
};
pub const CODECAPI_AVEncMP12MuxSysRateBound: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 99631754, data2: 60976, data3: 18589, data4: [174, 40, 32, 92, 114, 68, 103, 16] };
pub const CODECAPI_AVEncMP12MuxSysSTDBufferBound: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 896821507, data2: 46405, data3: 17383, data4: [187, 53, 197, 224, 167, 213, 9, 60] };
pub const CODECAPI_AVEncMP12MuxSysVideoLock: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3089720328,
    data2: 9264,
    data3: 19767,
    data4: [162, 161, 149, 179, 228, 53, 169, 29],
};
pub const CODECAPI_AVEncMP12MuxTargetPacketizer: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3630309674, data2: 8213, data3: 17885, data4: [154, 50, 27, 58, 168, 130, 5, 160] };
pub const CODECAPI_AVEncMP12PktzCopyright: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3371479233,
    data2: 2380,
    data3: 17351,
    data4: [142, 104, 165, 149, 64, 90, 110, 248],
};
pub const CODECAPI_AVEncMP12PktzInitialPTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 709828709, data2: 39523, data3: 19744, data4: [174, 34, 10, 27, 200, 150, 163, 21] };
pub const CODECAPI_AVEncMP12PktzOriginal: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1796703254,
    data2: 12729,
    data3: 18788,
    data4: [148, 203, 107, 255, 134, 108, 223, 131],
};
pub const CODECAPI_AVEncMP12PktzPacketSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2876322938,
    data2: 4914,
    data3: 19934,
    data4: [160, 229, 204, 247, 218, 138, 15, 34],
};
pub const CODECAPI_AVEncMP12PktzSTDBuffer: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 192224208, data2: 33182, data3: 18316, data4: [148, 53, 117, 32, 137, 38, 179, 119] };
pub const CODECAPI_AVEncMP12PktzStreamID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3358904376,
    data2: 62952,
    data3: 17416,
    data4: [155, 96, 136, 243, 100, 147, 254, 223],
};
pub const CODECAPI_AVEncMPACodingMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2976570883, data2: 19347, data3: 17367, data4: [165, 80, 144, 180, 254, 34, 69, 55] };
pub const CODECAPI_AVEncMPACopyright: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2796451370,
    data2: 53417,
    data3: 17492,
    data4: [184, 239, 242, 219, 238, 253, 211, 189],
};
pub const CODECAPI_AVEncMPAEmphasisType: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 760872154, data2: 48974, data3: 20182, data4: [181, 223, 91, 3, 179, 107, 10, 31] };
pub const CODECAPI_AVEncMPAEnableRedundancyProtection: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1582608542,
    data2: 45799,
    data3: 18803,
    data4: [168, 155, 11, 54, 80, 163, 190, 218],
};
pub const CODECAPI_AVEncMPALayer: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2637656624, data2: 63771, data3: 17725, data4: [156, 224, 120, 68, 84, 20, 194, 45] };
pub const CODECAPI_AVEncMPAOriginalBitstream: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1023113301,
    data2: 40137,
    data3: 18431,
    data4: [184, 41, 179, 103, 134, 201, 35, 70],
};
pub const CODECAPI_AVEncMPAPrivateUserBit: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2946827726, data2: 49635, data3: 20029, data4: [133, 27, 97, 183, 0, 229, 230, 204] };
pub const CODECAPI_AVEncMPVAddSeqEndCode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2820872079,
    data2: 22495,
    data3: 19578,
    data4: [184, 253, 229, 236, 136, 135, 112, 141],
};
pub const CODECAPI_AVEncMPVDefaultBPictureCount: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2369325740,
    data2: 56412,
    data3: 16896,
    data4: [181, 127, 129, 77, 4, 186, 186, 178],
};
pub const CODECAPI_AVEncMPVFrameFieldMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2897600150, data2: 31635, data3: 19503, data4: [136, 37, 176, 41, 95, 169, 59, 244] };
pub const CODECAPI_AVEncMPVGOPOpen: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2983580838, data2: 13056, data3: 18865, data4: [174, 97, 160, 153, 55, 171, 14, 73] };
pub const CODECAPI_AVEncMPVGOPSInSeq: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2570326228, data2: 9873, data3: 16786, data4: [153, 120, 152, 220, 38, 3, 102, 159] };
pub const CODECAPI_AVEncMPVGOPSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2515737382,
    data2: 38308,
    data3: 16810,
    data4: [147, 3, 36, 106, 127, 198, 238, 241],
};
pub const CODECAPI_AVEncMPVGOPSizeMax: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4269663428, data2: 6454, data3: 20450, data4: [189, 247, 31, 24, 202, 29, 0, 31] };
pub const CODECAPI_AVEncMPVGOPSizeMin: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1901448992,
    data2: 54336,
    data3: 18514,
    data4: [173, 15, 156, 74, 191, 227, 122, 106],
};
pub const CODECAPI_AVEncMPVGenerateHeaderPicDispExt: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3326160772,
    data2: 49215,
    data3: 20288,
    data4: [160, 12, 66, 147, 223, 131, 149, 187],
};
pub const CODECAPI_AVEncMPVGenerateHeaderPicExt: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461661355, data2: 37967, data3: 17904, data4: [183, 78, 58, 88, 218, 209, 31, 55] };
pub const CODECAPI_AVEncMPVGenerateHeaderSeqDispExt: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1681369711,
    data2: 23100,
    data3: 19945,
    data4: [138, 22, 83, 217, 196, 173, 50, 111],
};
pub const CODECAPI_AVEncMPVGenerateHeaderSeqExt: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3588720145, data2: 2093, data3: 20075, data4: [152, 175, 15, 81, 171, 19, 146, 34] };
pub const CODECAPI_AVEncMPVGenerateHeaderSeqScaleExt: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 119723567, data2: 56665, data3: 19078, data4: [156, 213, 100, 79, 142, 38, 83, 216] };
pub const CODECAPI_AVEncMPVIntraDCPrecision: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2685493585,
    data2: 52168,
    data3: 19187,
    data4: [151, 220, 208, 12, 206, 184, 45, 121],
};
pub const CODECAPI_AVEncMPVIntraVLCTable: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2729983989,
    data2: 6809,
    data3: 16474,
    data4: [175, 149, 197, 153, 125, 85, 141, 58],
};
pub const CODECAPI_AVEncMPVLevel: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1860439104, data2: 42508, data3: 16879, data4: [143, 80, 55, 194, 36, 158, 44, 179] };
pub const CODECAPI_AVEncMPVProfile: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3669709642, data2: 7577, data3: 17028, data4: [151, 90, 217, 14, 34, 57, 186, 161] };
pub const CODECAPI_AVEncMPVQScaleType: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 729410487,
    data2: 62596,
    data3: 19191,
    data4: [187, 88, 162, 161, 136, 197, 203, 190],
};
pub const CODECAPI_AVEncMPVQuantMatrixChromaIntra: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2662984916, data2: 397, data3: 20477, data4: [143, 45, 57, 228, 159, 7, 177, 122] };
pub const CODECAPI_AVEncMPVQuantMatrixChromaNonIntra: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 336967345, data2: 13866, data3: 17208, data4: [186, 154, 30, 245, 135, 3, 192, 91] };
pub const CODECAPI_AVEncMPVQuantMatrixIntra: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2615805171,
    data2: 26145,
    data3: 17452,
    data4: [139, 161, 58, 195, 120, 151, 150, 152],
};
pub const CODECAPI_AVEncMPVQuantMatrixNonIntra: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2280931800,
    data2: 2455,
    data3: 19435,
    data4: [160, 142, 133, 115, 212, 9, 207, 117],
};
pub const CODECAPI_AVEncMPVScanPattern: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2139768718,
    data2: 31675,
    data3: 19170,
    data4: [178, 252, 150, 209, 127, 196, 162, 214],
};
pub const CODECAPI_AVEncMPVSceneDetection: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1428658673, data2: 56140, data3: 16475, data4: [138, 58, 201, 63, 45, 6, 116, 220] };
pub const CODECAPI_AVEncMPVUseConcealmentMotionVectors: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3967225075,
    data2: 26888,
    data3: 19275,
    data4: [170, 48, 127, 185, 134, 33, 79, 234],
};
pub const CODECAPI_AVEncMaxFrameRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3113098033,
    data2: 6650,
    data3: 19791,
    data4: [153, 49, 214, 165, 184, 170, 185, 60],
};
pub const CODECAPI_AVEncMuxOutputStreamType: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3470630543, data2: 13523, data3: 17627, data4: [161, 216, 248, 21, 32, 37, 79, 62] };
pub const CODECAPI_AVEncNoInputCopy: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3535039018,
    data2: 59630,
    data3: 20165,
    data4: [134, 158, 68, 155, 108, 98, 200, 26],
};
pub const CODECAPI_AVEncNumWorkerThreads: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2965946208, data2: 5879, data3: 18769, data4: [163, 11, 29, 177, 96, 146, 147, 214] };
pub const CODECAPI_AVEncProgressiveUpdateTime: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1688186726,
    data2: 44998,
    data3: 18472,
    data4: [143, 220, 7, 113, 205, 154, 177, 125],
};
pub const CODECAPI_AVEncSliceControlMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3924263663,
    data2: 24344,
    data3: 17609,
    data4: [169, 11, 233, 195, 194, 193, 123, 11],
};
pub const CODECAPI_AVEncSliceControlSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2465537523,
    data2: 1957,
    data3: 16754,
    data4: [174, 254, 198, 156, 163, 182, 14, 53],
};
pub const CODECAPI_AVEncSliceGenerationMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2322318975,
    data2: 38039,
    data3: 17030,
    data4: [180, 107, 2, 219, 141, 96, 237, 188],
};
pub const CODECAPI_AVEncStatAudioAverageBPS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3395757275,
    data2: 28761,
    data3: 17233,
    data4: [139, 67, 248, 33, 152, 130, 106, 20],
};
pub const CODECAPI_AVEncStatAudioAveragePCMValue: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2542957304,
    data2: 53631,
    data3: 20018,
    data4: [187, 115, 78, 115, 28, 104, 186, 45],
};
pub const CODECAPI_AVEncStatAudioPeakPCMValue: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3706191156, data2: 56320, data3: 19478, data4: [130, 27, 53, 217, 235, 0, 251, 26] };
pub const CODECAPI_AVEncStatAverageBPS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3395757275,
    data2: 28761,
    data3: 17233,
    data4: [139, 67, 248, 33, 152, 130, 106, 20],
};
pub const CODECAPI_AVEncStatCommonCompletedPasses: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1046340915,
    data2: 40439,
    data3: 17292,
    data4: [133, 79, 159, 125, 211, 104, 61, 52],
};
pub const CODECAPI_AVEncStatHardwareBandwidthUtilitization: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 19184283, data2: 56385, data3: 18470, data4: [180, 95, 24, 172, 1, 179, 213, 168] };
pub const CODECAPI_AVEncStatHardwareProcessorUtilitization: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2573058087,
    data2: 52117,
    data3: 18918,
    data4: [185, 27, 89, 103, 117, 60, 220, 184],
};
pub const CODECAPI_AVEncStatMPVSkippedEmptyFrames: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 840523731, data2: 22797, data3: 18450, data4: [167, 237, 109, 99, 154, 31, 151, 17] };
pub const CODECAPI_AVEncStatVideoCodedFrames: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3565129057,
    data2: 28506,
    data3: 18982,
    data4: [187, 159, 205, 149, 24, 70, 43, 205],
};
pub const CODECAPI_AVEncStatVideoOutputFrameRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3195304009,
    data2: 39604,
    data3: 19043,
    data4: [152, 254, 241, 67, 240, 79, 142, 233],
};
pub const CODECAPI_AVEncStatVideoTotalFrames: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4255815958,
    data2: 4506,
    data3: 16930,
    data4: [154, 214, 63, 124, 171, 153, 204, 139],
};
pub const CODECAPI_AVEncStatWMVCBAvg: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1789272735,
    data2: 54786,
    data3: 19357,
    data4: [182, 140, 193, 173, 120, 136, 75, 239],
};
pub const CODECAPI_AVEncStatWMVCBMax: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3916873464, data2: 254, data3: 17588, data4: [182, 37, 143, 35, 139, 192, 52, 153] };
pub const CODECAPI_AVEncStatWMVDecoderComplexityProfile: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2313592771, data2: 3995, data3: 17260, data4: [151, 74, 223, 130, 18, 39, 201, 13] };
pub const CODECAPI_AVEncVideoCBRMotionTradeoff: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 222905630, data2: 6357, data3: 17255, data4: [164, 239, 50, 64, 223, 22, 147, 196] };
pub const CODECAPI_AVEncVideoCTBSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3565009074,
    data2: 59195,
    data3: 19641,
    data4: [140, 62, 189, 135, 125, 6, 215, 123],
};
pub const CODECAPI_AVEncVideoCodedVideoAccessUnitSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3031501845,
    data2: 5287,
    data3: 19688,
    data4: [177, 115, 220, 144, 160, 180, 252, 219],
};
pub const CODECAPI_AVEncVideoContentType: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1712421578,
    data2: 60279,
    data3: 17821,
    data4: [147, 12, 164, 141, 157, 6, 131, 252],
};
pub const CODECAPI_AVEncVideoDefaultUpperFieldDominant: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2164352964, data2: 3009, data3: 18378, data4: [143, 194, 87, 5, 90, 20, 116, 165] };
pub const CODECAPI_AVEncVideoDirtyRectEnabled: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2328596445, data2: 24076, data3: 19558, data4: [135, 41, 184, 246, 41, 171, 4, 251] };
pub const CODECAPI_AVEncVideoDisplayDimension: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3724883560,
    data2: 62700,
    data3: 18345,
    data4: [134, 208, 131, 103, 112, 240, 193, 213],
};
pub const CODECAPI_AVEncVideoEncodeDimension: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 276094760,
    data2: 32271,
    data3: 18340,
    data4: [164, 83, 205, 215, 56, 112, 245, 206],
};
pub const CODECAPI_AVEncVideoEncodeFrameTypeQP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2859513360, data2: 57407, data3: 17676, data4: [173, 7, 7, 49, 78, 99, 156, 231] };
pub const CODECAPI_AVEncVideoEncodeOffsetOrigin: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1807784190, data2: 42778, data3: 17492, data4: [133, 46, 77, 45, 222, 178, 205, 36] };
pub const CODECAPI_AVEncVideoEncodeQP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 750086507, data2: 9211, data3: 19681, data4: [160, 249, 239, 91, 144, 253, 85, 202] };
pub const CODECAPI_AVEncVideoFieldSwap: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4278023529, data2: 19978, data3: 18930, data4: [159, 43, 54, 14, 164, 140, 25, 162] };
pub const CODECAPI_AVEncVideoForceKeyFrame: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 965483416, data2: 33619, data3: 18266, data4: [158, 242, 143, 38, 93, 38, 3, 69] };
pub const CODECAPI_AVEncVideoForceSourceScanType: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 519177823, data2: 1418, data3: 18277, data4: [164, 252, 138, 134, 76, 16, 48, 18] };
pub const CODECAPI_AVEncVideoGradualIntraRefresh: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2402581998, data2: 51981, data3: 18874, data4: [180, 98, 219, 105, 39, 238, 33, 1] };
pub const CODECAPI_AVEncVideoHeaderDropFrame: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1859772708, data2: 31013, data3: 17406, data4: [151, 27, 224, 25, 246, 34, 34, 180] };
pub const CODECAPI_AVEncVideoHeaderFrames: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2950034791, data2: 23579, data3: 19164, data4: [189, 175, 115, 86, 16, 56, 20, 54] };
pub const CODECAPI_AVEncVideoHeaderHours: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 718042882, data2: 58074, data3: 16728, data4: [191, 155, 136, 136, 1, 41, 215, 64] };
pub const CODECAPI_AVEncVideoHeaderMinutes: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3692730830, data2: 775, data3: 16523, data4: [136, 11, 184, 52, 142, 232, 202, 127] };
pub const CODECAPI_AVEncVideoHeaderSeconds: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1244535301,
    data2: 42880,
    data3: 20312,
    data4: [129, 32, 154, 68, 157, 105, 101, 107],
};
pub const CODECAPI_AVEncVideoInputChromaResolution: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3138186291, data2: 5873, data3: 18352, data4: [138, 136, 55, 129, 91, 238, 23, 57] };
pub const CODECAPI_AVEncVideoInputChromaSubsampling: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2833726009, data2: 17461, data3: 20163, data4: [166, 234, 152, 48, 15, 75, 54, 247] };
pub const CODECAPI_AVEncVideoInputColorLighting: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1185518921, data2: 21, data3: 19013, data4: [156, 48, 29, 92, 250, 37, 131, 22] };
pub const CODECAPI_AVEncVideoInputColorNominalRange: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 382674374, data2: 41638, data3: 18665, data4: [174, 128, 33, 174, 196, 29, 66, 126] };
pub const CODECAPI_AVEncVideoInputColorPrimaries: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3259856959,
    data2: 31974,
    data3: 17016,
    data4: [144, 171, 40, 164, 241, 229, 248, 108],
};
pub const CODECAPI_AVEncVideoInputColorTransferFunction: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2349162769,
    data2: 43459,
    data3: 19208,
    data4: [160, 160, 206, 19, 248, 162, 124, 117],
};
pub const CODECAPI_AVEncVideoInputColorTransferMatrix: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1391290553, data2: 29397, data3: 16521, data4: [149, 141, 245, 64, 93, 85, 8, 28] };
pub const CODECAPI_AVEncVideoInstantTemporalUpSwitching: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2737865479, data2: 3478, data3: 19364, data4: [177, 240, 185, 26, 94, 73, 223, 16] };
pub const CODECAPI_AVEncVideoIntraLayerPrediction: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3551479480,
    data2: 48967,
    data3: 17595,
    data4: [162, 131, 105, 240, 176, 34, 143, 249],
};
pub const CODECAPI_AVEncVideoInverseTelecineEnable: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 782829963,
    data2: 59245,
    data3: 19661,
    data4: [160, 48, 211, 184, 137, 193, 182, 76],
};
pub const CODECAPI_AVEncVideoInverseTelecineThreshold: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1076133252, data2: 59541, data3: 18815, data4: [180, 76, 183, 69, 96, 172, 254, 39] };
pub const CODECAPI_AVEncVideoLTRBufferControl: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2762008893,
    data2: 19644,
    data3: 17484,
    data4: [137, 244, 130, 109, 49, 14, 146, 167],
};
pub const CODECAPI_AVEncVideoMarkLTRFrame: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3828303688, data2: 41069, data3: 20217, data4: [140, 234, 61, 5, 253, 227, 189, 59] };
pub const CODECAPI_AVEncVideoMaxCTBSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2183357439,
    data2: 52936,
    data3: 17381,
    data4: [146, 253, 224, 151, 72, 132, 133, 233],
};
pub const CODECAPI_AVEncVideoMaxKeyframeDistance: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 696717882, data2: 47763, data3: 18180, data4: [180, 137, 236, 30, 95, 37, 41, 44] };
pub const CODECAPI_AVEncVideoMaxNumRefFrame: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2521311725,
    data2: 38137,
    data3: 17332,
    data4: [183, 77, 239, 64, 148, 75, 105, 160],
};
pub const CODECAPI_AVEncVideoMaxQP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1034907494,
    data2: 42663,
    data3: 17888,
    data4: [168, 229, 242, 116, 63, 70, 163, 162],
};
pub const CODECAPI_AVEncVideoMaxTemporalLayers: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2623966462,
    data2: 2273,
    data3: 16970,
    data4: [147, 78, 183, 100, 176, 100, 128, 42],
};
pub const CODECAPI_AVEncVideoMeanAbsoluteDifference: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3854614799, data2: 33188, data3: 16941, data4: [140, 63, 180, 116, 164, 88, 19, 54] };
pub const CODECAPI_AVEncVideoMinQP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 249703530, data2: 41852, data3: 17768, data4: [181, 241, 157, 76, 43, 58, 184, 134] };
pub const CODECAPI_AVEncVideoNoOfFieldsToEncode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1642380258,
    data2: 20192,
    data3: 16615,
    data4: [128, 171, 81, 221, 238, 190, 98, 145],
};
pub const CODECAPI_AVEncVideoNoOfFieldsToSkip: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2843611712,
    data2: 5159,
    data3: 19478,
    data4: [167, 247, 61, 207, 216, 186, 76, 197],
};
pub const CODECAPI_AVEncVideoNumGOPsPerIDR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2210159579, data2: 23433, data3: 17697, data4: [143, 102, 51, 21, 28, 55, 49, 118] };
pub const CODECAPI_AVEncVideoOutputChromaResolution: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1620554953,
    data2: 31773,
    data3: 20068,
    data4: [191, 204, 158, 151, 101, 49, 138, 231],
};
pub const CODECAPI_AVEncVideoOutputChromaSubsampling: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4199947372, data2: 32023, data3: 17648, data4: [131, 201, 50, 237, 18, 233, 99, 67] };
pub const CODECAPI_AVEncVideoOutputColorLighting: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 240822982,
    data2: 44262,
    data3: 19548,
    data4: [153, 142, 26, 140, 156, 108, 15, 137],
};
pub const CODECAPI_AVEncVideoOutputColorNominalRange: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2535994861, data2: 34741, data3: 20117, data4: [149, 0, 199, 57, 88, 86, 110, 84] };
pub const CODECAPI_AVEncVideoOutputColorPrimaries: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3197472892,
    data2: 40196,
    data3: 18721,
    data4: [137, 133, 166, 214, 216, 125, 26, 108],
};
pub const CODECAPI_AVEncVideoOutputColorTransferFunction: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1249871946, data2: 59921, data3: 17933, data4: [191, 87, 184, 139, 199, 89, 0, 222] };
pub const CODECAPI_AVEncVideoOutputColorTransferMatrix: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2847474756,
    data2: 44864,
    data3: 17168,
    data4: [143, 190, 237, 109, 147, 63, 137, 43],
};
pub const CODECAPI_AVEncVideoOutputFrameRate: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3934644163,
    data2: 38247,
    data3: 19865,
    data4: [135, 196, 2, 193, 194, 120, 202, 124],
};
pub const CODECAPI_AVEncVideoOutputFrameRateConversion: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2349239284,
    data2: 13978,
    data3: 19363,
    data4: [130, 253, 178, 81, 143, 179, 57, 110],
};
pub const CODECAPI_AVEncVideoOutputScanType: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1175147894,
    data2: 33838,
    data3: 18859,
    data4: [166, 45, 179, 111, 115, 18, 201, 219],
};
pub const CODECAPI_AVEncVideoPixelAspectRatio: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1021079951, data2: 46057, data3: 20150, data4: [165, 127, 207, 31, 27, 50, 27, 135] };
pub const CODECAPI_AVEncVideoROIEnabled: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3612311320,
    data2: 17629,
    data3: 19333,
    data4: [171, 163, 5, 217, 244, 42, 130, 128],
};
pub const CODECAPI_AVEncVideoRateControlParams: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2278831975,
    data2: 30277,
    data3: 17644,
    data4: [180, 56, 211, 50, 47, 188, 162, 159],
};
pub const CODECAPI_AVEncVideoSelectLayer: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3943728373, data2: 27306, data3: 18708, data4: [187, 47, 97, 71, 34, 127, 18, 231] };
pub const CODECAPI_AVEncVideoSourceFilmContent: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 395429451, data2: 52476, data3: 18471, data4: [160, 237, 37, 87, 121, 59, 43, 28] };
pub const CODECAPI_AVEncVideoSourceIsBW: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1124058267, data2: 6162, data3: 20444, data4: [141, 36, 112, 84, 197, 33, 230, 235] };
pub const CODECAPI_AVEncVideoSupportedControls: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3555987421, data2: 30649, data3: 18237, data4: [129, 150, 6, 18, 89, 230, 156, 255] };
pub const CODECAPI_AVEncVideoTemporalLayerCount: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 432729087, data2: 46925, data3: 19709, data4: [140, 39, 194, 249, 217, 125, 95, 82] };
pub const CODECAPI_AVEncVideoUsage: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 526608457,
    data2: 24001,
    data3: 18929,
    data4: [177, 216, 206, 60, 246, 46, 163, 133],
};
pub const CODECAPI_AVEncVideoUseLTRFrame: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 7679416, data2: 22007, data3: 20352, data4: [137, 91, 39, 99, 145, 149, 242, 173] };
pub const CODECAPI_AVEncWMVDecoderComplexity: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4079750571,
    data2: 62411,
    data3: 16919,
    data4: [183, 159, 135, 98, 118, 139, 95, 103],
};
pub const CODECAPI_AVEncWMVInterlacedEncoding: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3822063498,
    data2: 50933,
    data3: 19988,
    data4: [165, 136, 14, 200, 122, 114, 111, 155],
};
pub const CODECAPI_AVEncWMVKeyFrameBufferLevelMarker: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1375670549, data2: 13228, data3: 17004, data4: [161, 177, 9, 50, 27, 223, 150, 180] };
pub const CODECAPI_AVEncWMVKeyFrameDistance: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1432946014,
    data2: 57960,
    data3: 18289,
    data4: [184, 62, 149, 85, 234, 40, 174, 211],
};
pub const CODECAPI_AVEncWMVProduceDummyFrames: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3597258753, data2: 6204, data3: 17123, data4: [163, 202, 47, 69, 134, 210, 57, 108] };
pub const CODECAPI_AVLowLatencyMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2619836698,
    data2: 60794,
    data3: 16609,
    data4: [136, 232, 178, 39, 39, 160, 36, 238],
};
pub const CODECAPI_AVPriorityControl: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1421491656, data2: 48606, data3: 17193, data4: [177, 135, 32, 24, 188, 92, 43, 161] };
pub const CODECAPI_AVRealtimeControl: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1866729010, data2: 50349, data3: 19447, data4: [158, 82, 69, 105, 66, 180, 84, 176] };
pub const CODECAPI_AVScenarioInfo: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2995416676, data2: 16377, data3: 17514, data4: [138, 75, 13, 122, 83, 65, 50, 54] };
pub const CODECAPI_GUID_AVDecAudioInputAAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2548004904, data2: 47434, data3: 18402, data4: [164, 188, 81, 25, 77, 178, 42, 77] };
pub const CODECAPI_GUID_AVDecAudioInputDTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1611382986,
    data2: 27167,
    data3: 20113,
    data4: [178, 65, 27, 190, 177, 203, 25, 224],
};
pub const CODECAPI_GUID_AVDecAudioInputDolby: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2386700448,
    data2: 61440,
    data3: 19979,
    data4: [143, 84, 171, 141, 36, 173, 97, 162],
};
pub const CODECAPI_GUID_AVDecAudioInputDolbyDigitalPlus: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 134472069, data2: 36701, data3: 18421, data4: [153, 8, 25, 165, 187, 201, 254, 52] };
pub const CODECAPI_GUID_AVDecAudioInputHEAAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 384808106,
    data2: 13070,
    data3: 20316,
    data4: [152, 168, 207, 106, 197, 92, 190, 96],
};
pub const CODECAPI_GUID_AVDecAudioInputMPEG: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2433773366, data2: 709, data3: 20341, data4: [151, 25, 59, 122, 191, 117, 225, 246] };
pub const CODECAPI_GUID_AVDecAudioInputPCM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4064419237, data2: 48052, data3: 19669, data4: [169, 150, 147, 60, 107, 93, 19, 71] };
pub const CODECAPI_GUID_AVDecAudioInputWMA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3378417103, data2: 16472, data3: 16900, data4: [140, 66, 203, 36, 217, 30, 75, 155] };
pub const CODECAPI_GUID_AVDecAudioInputWMAPro: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 19445703, data2: 55922, data3: 20451, data4: [190, 248, 92, 82, 227, 85, 119, 4] };
pub const CODECAPI_GUID_AVDecAudioOutputFormat_PCM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1768824113, data2: 21647, data3: 16438, data4: [130, 95, 112, 38, 198, 0, 17, 189] };
pub const CODECAPI_GUID_AVDecAudioOutputFormat_PCM_Headphones: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1768824116, data2: 21647, data3: 16438, data4: [130, 95, 112, 38, 198, 0, 17, 189] };
pub const CODECAPI_GUID_AVDecAudioOutputFormat_PCM_Stereo_Auto: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1768824117, data2: 21647, data3: 16438, data4: [130, 95, 112, 38, 198, 0, 17, 189] };
pub const CODECAPI_GUID_AVDecAudioOutputFormat_PCM_Stereo_MatrixEncoded: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1768824112, data2: 21647, data3: 16438, data4: [130, 95, 112, 38, 198, 0, 17, 189] };
pub const CODECAPI_GUID_AVDecAudioOutputFormat_SPDIF_Bitstream: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1768824115, data2: 21647, data3: 16438, data4: [130, 95, 112, 38, 198, 0, 17, 189] };
pub const CODECAPI_GUID_AVDecAudioOutputFormat_SPDIF_PCM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1768824114, data2: 21647, data3: 16438, data4: [130, 95, 112, 38, 198, 0, 17, 189] };
pub const CODECAPI_GUID_AVEncCommonFormatATSC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2373683580,
    data2: 40985,
    data3: 18032,
    data4: [170, 118, 46, 220, 172, 122, 194, 150],
};
pub const CODECAPI_GUID_AVEncCommonFormatDVB: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1904414095,
    data2: 27699,
    data3: 17165,
    data4: [132, 75, 194, 112, 91, 170, 230, 219],
};
pub const CODECAPI_GUID_AVEncCommonFormatDVD_DashVR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3847330262, data2: 1100, data3: 19886, data4: [164, 136, 83, 30, 211, 6, 35, 91] };
pub const CODECAPI_GUID_AVEncCommonFormatDVD_PlusVR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3880546094,
    data2: 60471,
    data3: 18317,
    data4: [154, 244, 165, 225, 53, 182, 39, 28],
};
pub const CODECAPI_GUID_AVEncCommonFormatDVD_V: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3432356036,
    data2: 59390,
    data3: 17693,
    data4: [177, 202, 118, 27, 200, 64, 183, 243],
};
pub const CODECAPI_GUID_AVEncCommonFormatHighMAT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 514582368,
    data2: 64299,
    data3: 18728,
    data4: [144, 209, 120, 219, 136, 238, 232, 137],
};
pub const CODECAPI_GUID_AVEncCommonFormatHighMPV: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2731695544,
    data2: 47353,
    data3: 17090,
    data4: [139, 199, 11, 147, 207, 96, 71, 136],
};
pub const CODECAPI_GUID_AVEncCommonFormatMP3: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 882324429,
    data2: 60168,
    data3: 19906,
    data4: [129, 151, 228, 152, 53, 239, 130, 139],
};
pub const CODECAPI_GUID_AVEncCommonFormatSVCD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1373132824,
    data2: 33312,
    data3: 17548,
    data4: [128, 102, 214, 155, 237, 22, 201, 173],
};
pub const CODECAPI_GUID_AVEncCommonFormatUnSpecified: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2940642138,
    data2: 24612,
    data3: 17701,
    data4: [164, 138, 9, 75, 151, 245, 179, 194],
};
pub const CODECAPI_GUID_AVEncCommonFormatVCD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2500025335,
    data2: 40336,
    data3: 16639,
    data4: [173, 92, 92, 248, 207, 113, 202, 29],
};
pub const CODECAPI_GUID_AVEncDTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1174129314, data2: 24174, data3: 19120, data4: [136, 147, 89, 3, 190, 233, 58, 207] };
pub const CODECAPI_GUID_AVEncDTSHD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 542303792,
    data2: 18077,
    data3: 19451,
    data4: [128, 202, 29, 101, 110, 126, 145, 143],
};
pub const CODECAPI_GUID_AVEncDV: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 163015111, data2: 13097, data3: 17659, data4: [137, 84, 250, 48, 147, 125, 61, 90] };
pub const CODECAPI_GUID_AVEncDolbyDigitalConsumer: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3248996204, data2: 89, data3: 19450, data4: [148, 239, 239, 116, 122, 118, 141, 82] };
pub const CODECAPI_GUID_AVEncDolbyDigitalPlus: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1770855296, data2: 63453, data3: 16732, data4: [151, 28, 66, 73, 42, 32, 86, 198] };
pub const CODECAPI_GUID_AVEncDolbyDigitalPro: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4122900172, data2: 4088, data3: 16619, data4: [156, 177, 187, 169, 64, 4, 212, 79] };
pub const CODECAPI_GUID_AVEncH264Video: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2500087467, data2: 12723, data3: 18398, data4: [142, 117, 56, 164, 43, 176, 62, 40] };
pub const CODECAPI_GUID_AVEncMLP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 100089385, data2: 61649, data3: 17182, data4: [164, 28, 164, 116, 50, 236, 90, 102] };
pub const CODECAPI_GUID_AVEncMPEG1Audio: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3571258210, data2: 52554, data3: 19670, data4: [129, 56, 185, 77, 180, 84, 43, 4] };
pub const CODECAPI_GUID_AVEncMPEG1Video: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3369795326,
    data2: 55838,
    data3: 18292,
    data4: [178, 125, 17, 131, 12, 22, 177, 254],
};
pub const CODECAPI_GUID_AVEncMPEG2Audio: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3998006047,
    data2: 39999,
    data3: 18288,
    data4: [146, 181, 252, 183, 194, 168, 211, 129],
};
pub const CODECAPI_GUID_AVEncMPEG2Video: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 74301850, data2: 26231, data3: 19114, data4: [163, 29, 193, 171, 113, 111, 69, 96] };
pub const CODECAPI_GUID_AVEncPCM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2219567092, data2: 9935, data3: 18297, data4: [179, 134, 204, 5, 209, 135, 153, 12] };
pub const CODECAPI_GUID_AVEncSDDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 499234863, data2: 4552, data3: 19569, data4: [183, 182, 238, 62, 185, 188, 43, 148] };
pub const CODECAPI_GUID_AVEncWMALossless: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1439330917, data2: 9176, data3: 18273, data4: [144, 49, 183, 79, 190, 18, 244, 193] };
pub const CODECAPI_GUID_AVEncWMAPro: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 425064716,
    data2: 13303,
    data3: 19048,
    data4: [171, 129, 83, 245, 101, 113, 37, 196],
};
pub const CODECAPI_GUID_AVEncWMAVoice: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 334305483,
    data2: 20712,
    data3: 17014,
    data4: [162, 136, 166, 170, 34, 131, 130, 217],
};
pub const CODECAPI_GUID_AVEncWMV: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1309667227, data2: 7491, data3: 16829, data4: [184, 189, 77, 123, 247, 69, 122, 42] };
pub const CODECAPI_GUID_AVEndMPEG4Video: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3711414570, data2: 38147, data3: 20363, data4: [184, 208, 50, 74, 0, 192, 161, 207] };
pub const CODECAPI_GetOPMContext: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 788753413, data2: 19476, data3: 18057, data4: [136, 57, 41, 76, 109, 115, 224, 83] };
pub const CODECAPI_SetHDCPManagerContext: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1831673800,
    data2: 15817,
    data3: 18411,
    data4: [161, 162, 71, 28, 128, 205, 96, 208],
};
pub const CODECAPI_VideoEncoderDisplayContentType: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2042170151,
    data2: 62641,
    data3: 17116,
    data4: [157, 215, 205, 175, 129, 53, 196, 0],
};
pub const COPP_ProtectionType_ACP: i32 = 2i32;
pub const COPP_ProtectionType_CGMSA: i32 = 4i32;
pub const COPP_ProtectionType_HDCP: i32 = 1i32;
pub const COPP_ProtectionType_Mask: i32 = -2147483641i32;
pub const COPP_ProtectionType_None: i32 = 0i32;
pub const COPP_ProtectionType_Reserved: i32 = 2147483640i32;
pub const COPP_ProtectionType_Unknown: i32 = -2147483648i32;
pub const CPK_DS_AC3Decoder: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1822190038,
    data2: 4092,
    data3: 17537,
    data4: [175, 219, 205, 241, 199, 156, 111, 62],
};
pub const CPK_DS_MPEG2Decoder: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2568013261,
    data2: 38345,
    data3: 19974,
    data4: [134, 90, 239, 161, 200, 1, 107, 244],
};
pub const CResamplerMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4098340510,
    data2: 6276,
    data3: 19070,
    data4: [128, 85, 52, 111, 116, 214, 237, 179],
};
pub const CResizerDMO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 513927700, data2: 18676, data3: 16468, data4: [173, 26, 232, 174, 225, 10, 200, 5] };
pub const CResizerMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3555494795,
    data2: 30504,
    data3: 20440,
    data4: [159, 224, 123, 103, 209, 159, 115, 163],
};
pub const CShotDetectorDmo: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1454308045,
    data2: 4364,
    data3: 17303,
    data4: [146, 146, 176, 160, 198, 27, 103, 80],
};
pub const CSmpteTransformsDmo: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3185981579, data2: 55845, data3: 18525, data4: [186, 127, 250, 188, 40, 178, 3, 24] };
pub const CThumbnailGeneratorDmo: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1436314541,
    data2: 7848,
    data3: 18787,
    data4: [160, 135, 138, 104, 16, 249, 33, 139],
};
pub const CTocGeneratorDmo: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1306138945, data2: 30624, data3: 20401, data4: [165, 24, 226, 24, 80, 65, 215, 12] };
pub const CVodafoneAACCCDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2121711487,
    data2: 51603,
    data3: 20006,
    data4: [143, 171, 71, 10, 112, 192, 213, 156],
};
pub const CVodafoneAACDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2134309186, data2: 56563, data3: 19842, data4: [146, 137, 91, 24, 32, 39, 143, 124] };
pub const CWMADecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 787172063, data2: 17784, data3: 19728, data4: [188, 167, 187, 149, 95, 86, 50, 10] };
pub const CWMAEncMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1895143657,
    data2: 62635,
    data3: 18778,
    data4: [153, 226, 167, 196, 211, 216, 154, 191],
};
pub const CWMATransMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3989494219, data2: 12583, data3: 16607, data4: [181, 39, 1, 82, 204, 179, 246, 245] };
pub const CWMAudioAEC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1951422407, data2: 62291, data3: 20269, data4: [167, 238, 88, 67, 68, 119, 115, 14] };
pub const CWMAudioCAPXGFXAPO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 329989821, data2: 4990, data3: 18691, data4: [157, 137, 96, 190, 130, 119, 253, 23] };
pub const CWMAudioCAPXLFXAPO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3376758387,
    data2: 35932,
    data3: 17507,
    data4: [153, 132, 175, 139, 171, 47, 84, 71],
};
pub const CWMAudioGFXAPO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1669089549, data2: 61155, data3: 19466, data4: [151, 63, 55, 25, 88, 128, 45, 162] };
pub const CWMAudioLFXAPO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1658591891, data2: 44580, data3: 17996, data4: [164, 62, 69, 47, 130, 76, 66, 80] };
pub const CWMAudioSpdTxDMO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1376844004,
    data2: 45243,
    data3: 18371,
    data4: [168, 217, 123, 34, 130, 204, 121, 237],
};
pub const CWMSPDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2269196747, data2: 20172, data3: 17467, data4: [137, 72, 116, 107, 137, 89, 93, 32] };
pub const CWMSPEncMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1736710915,
    data2: 50825,
    data3: 16776,
    data4: [173, 63, 76, 158, 190, 236, 113, 11],
};
pub const CWMSPEncMediaObject2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 522145306, data2: 8786, data3: 16483, data4: [132, 187, 238, 231, 95, 136, 86, 213] };
pub const CWMTDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4191929934, data2: 11728, data3: 17885, data4: [155, 82, 102, 100, 46, 249, 68, 49] };
pub const CWMTEncMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1622570578, data2: 58475, data3: 20036, data4: [134, 9, 247, 75, 255, 220, 8, 60] };
pub const CWMV9EncMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3527119056, data2: 5199, data3: 18109, data4: [132, 29, 89, 228, 235, 25, 220, 89] };
pub const CWMVDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2194887647,
    data2: 37053,
    data3: 17282,
    data4: [139, 194, 63, 97, 146, 183, 110, 52],
};
pub const CWMVEncMediaObject2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2528476381, data2: 35174, data3: 16652, data4: [187, 31, 201, 126, 234, 118, 92, 4] };
pub const CWMVXEncMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2117206162, data2: 22890, data3: 16818, data4: [187, 235, 23, 93, 16, 80, 78, 182] };
pub const CWVC1DecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3384786127,
    data2: 58894,
    data3: 17800,
    data4: [163, 223, 90, 3, 177, 253, 149, 133],
};
pub const CWVC1EncMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1147485453,
    data2: 36042,
    data3: 16871,
    data4: [186, 202, 136, 67, 55, 183, 71, 172],
};
pub const CZuneAACCCDecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2806946034,
    data2: 21206,
    data3: 19278,
    data4: [136, 91, 224, 166, 202, 79, 24, 122],
};
pub const CZuneM4S2DecMediaObject: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3312435804, data2: 4038, data3: 16458, data4: [149, 3, 177, 11, 245, 26, 138, 185] };
#[repr(C)]
pub struct CodecAPIEventData {
    pub guid: ::windows_sys::core::GUID,
    pub dataLength: u32,
    pub reserved: [u32; 3],
}
impl ::core::marker::Copy for CodecAPIEventData {}
impl ::core::clone::Clone for CodecAPIEventData {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_BITSTREAM_ENCRYPTION_TYPE = i32;
pub const D3D12_BITSTREAM_ENCRYPTION_TYPE_NONE: D3D12_BITSTREAM_ENCRYPTION_TYPE = 0i32;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ARCHITECTURE {
    pub IOCoherent: super::super::Foundation::BOOL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ARCHITECTURE {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ARCHITECTURE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODER_HEAP_SIZE {
    pub VideoDecoderHeapDesc: D3D12_VIDEO_DECODER_HEAP_DESC,
    pub MemoryPoolL0Size: u64,
    pub MemoryPoolL1Size: u64,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODER_HEAP_SIZE {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODER_HEAP_SIZE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODER_HEAP_SIZE1 {
    pub VideoDecoderHeapDesc: D3D12_VIDEO_DECODER_HEAP_DESC,
    pub Protected: super::super::Foundation::BOOL,
    pub MemoryPoolL0Size: u64,
    pub MemoryPoolL1Size: u64,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODER_HEAP_SIZE1 {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODER_HEAP_SIZE1 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODE_CONVERSION_SUPPORT {
    pub NodeIndex: u32,
    pub Configuration: D3D12_VIDEO_DECODE_CONFIGURATION,
    pub DecodeSample: D3D12_VIDEO_SAMPLE,
    pub OutputFormat: D3D12_VIDEO_FORMAT,
    pub FrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub BitRate: u32,
    pub SupportFlags: D3D12_VIDEO_DECODE_CONVERSION_SUPPORT_FLAGS,
    pub ScaleSupport: D3D12_VIDEO_SCALE_SUPPORT,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODE_CONVERSION_SUPPORT {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODE_CONVERSION_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODE_FORMATS {
    pub NodeIndex: u32,
    pub Configuration: D3D12_VIDEO_DECODE_CONFIGURATION,
    pub FormatCount: u32,
    pub pOutputFormats: *mut super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODE_FORMATS {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODE_FORMATS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODE_FORMAT_COUNT {
    pub NodeIndex: u32,
    pub Configuration: D3D12_VIDEO_DECODE_CONFIGURATION,
    pub FormatCount: u32,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODE_FORMAT_COUNT {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODE_FORMAT_COUNT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODE_HISTOGRAM {
    pub NodeIndex: u32,
    pub DecodeProfile: ::windows_sys::core::GUID,
    pub Width: u32,
    pub Height: u32,
    pub DecodeFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub Components: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS,
    pub BinCount: u32,
    pub CounterBitDepth: u32,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODE_HISTOGRAM {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODE_HISTOGRAM {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILES {
    pub NodeIndex: u32,
    pub ProfileCount: u32,
    pub pProfiles: *mut ::windows_sys::core::GUID,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILES {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILES {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILE_COUNT {
    pub NodeIndex: u32,
    pub ProfileCount: u32,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILE_COUNT {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODE_PROFILE_COUNT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODE_PROTECTED_RESOURCES {
    pub NodeIndex: u32,
    pub Configuration: D3D12_VIDEO_DECODE_CONFIGURATION,
    pub SupportFlags: D3D12_VIDEO_PROTECTED_RESOURCE_SUPPORT_FLAGS,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODE_PROTECTED_RESOURCES {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODE_PROTECTED_RESOURCES {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_FEATURE_DATA_VIDEO_DECODE_SUPPORT {
    pub NodeIndex: u32,
    pub Configuration: D3D12_VIDEO_DECODE_CONFIGURATION,
    pub Width: u32,
    pub Height: u32,
    pub DecodeFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub FrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub BitRate: u32,
    pub SupportFlags: D3D12_VIDEO_DECODE_SUPPORT_FLAGS,
    pub ConfigurationFlags: D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS,
    pub DecodeTier: D3D12_VIDEO_DECODE_TIER,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_DECODE_SUPPORT {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_DECODE_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_CODEC {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub IsSupported: super::super::Foundation::BOOL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_CODEC {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_CODEC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub Profile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub IsSupported: super::super::Foundation::BOOL,
    pub CodecSupportLimits: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub Profile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub IsSupported: super::super::Foundation::BOOL,
    pub PictureSupport: D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub Profile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub Level: D3D12_VIDEO_ENCODER_LEVEL_SETTING,
    pub SubregionMode: D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE,
    pub IsSupported: super::super::Foundation::BOOL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_HEAP_SIZE {
    pub HeapDesc: D3D12_VIDEO_ENCODER_HEAP_DESC,
    pub IsSupported: super::super::Foundation::BOOL,
    pub MemoryPoolL0Size: u64,
    pub MemoryPoolL1Size: u64,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_HEAP_SIZE {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_HEAP_SIZE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_INPUT_FORMAT {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub Profile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub Format: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub IsSupported: super::super::Foundation::BOOL,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_INPUT_FORMAT {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_INPUT_FORMAT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_INTRA_REFRESH_MODE {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub Profile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub Level: D3D12_VIDEO_ENCODER_LEVEL_SETTING,
    pub IntraRefreshMode: D3D12_VIDEO_ENCODER_INTRA_REFRESH_MODE,
    pub IsSupported: super::super::Foundation::BOOL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_INTRA_REFRESH_MODE {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_INTRA_REFRESH_MODE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_OUTPUT_RESOLUTION {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub ResolutionRatiosCount: u32,
    pub IsSupported: super::super::Foundation::BOOL,
    pub MinResolutionSupported: D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC,
    pub MaxResolutionSupported: D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC,
    pub ResolutionWidthMultipleRequirement: u32,
    pub ResolutionHeightMultipleRequirement: u32,
    pub pResolutionRatios: *mut D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_RATIO_DESC,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_OUTPUT_RESOLUTION {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_OUTPUT_RESOLUTION {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_OUTPUT_RESOLUTION_RATIOS_COUNT {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub ResolutionRatiosCount: u32,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_OUTPUT_RESOLUTION_RATIOS_COUNT {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_OUTPUT_RESOLUTION_RATIOS_COUNT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_PROFILE_LEVEL {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub Profile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub IsSupported: super::super::Foundation::BOOL,
    pub MinSupportedLevel: D3D12_VIDEO_ENCODER_LEVEL_SETTING,
    pub MaxSupportedLevel: D3D12_VIDEO_ENCODER_LEVEL_SETTING,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_PROFILE_LEVEL {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_PROFILE_LEVEL {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_RATE_CONTROL_MODE {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub RateControlMode: D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE,
    pub IsSupported: super::super::Foundation::BOOL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_RATE_CONTROL_MODE {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_RATE_CONTROL_MODE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_RESOLUTION_SUPPORT_LIMITS {
    pub MaxSubregionsNumber: u32,
    pub MaxIntraRefreshFrameDuration: u32,
    pub SubregionBlockPixelsSize: u32,
    pub QPMapRegionPixelsSize: u32,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_RESOLUTION_SUPPORT_LIMITS {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_RESOLUTION_SUPPORT_LIMITS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_RESOURCE_REQUIREMENTS {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub Profile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub InputFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub PictureTargetResolution: D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC,
    pub IsSupported: super::super::Foundation::BOOL,
    pub CompressedBitstreamBufferAccessAlignment: u32,
    pub EncoderMetadataBufferAccessAlignment: u32,
    pub MaxEncoderOutputMetadataBufferSize: u32,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_RESOURCE_REQUIREMENTS {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_RESOURCE_REQUIREMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_FEATURE_DATA_VIDEO_ENCODER_SUPPORT {
    pub NodeIndex: u32,
    pub Codec: D3D12_VIDEO_ENCODER_CODEC,
    pub InputFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub CodecConfiguration: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION,
    pub CodecGopSequence: D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE,
    pub RateControl: D3D12_VIDEO_ENCODER_RATE_CONTROL,
    pub IntraRefresh: D3D12_VIDEO_ENCODER_INTRA_REFRESH_MODE,
    pub SubregionFrameEncoding: D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE,
    pub ResolutionsListCount: u32,
    pub pResolutionList: *mut D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC,
    pub MaxReferenceFramesInDPB: u32,
    pub ValidationFlags: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS,
    pub SupportFlags: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS,
    pub SuggestedProfile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub SuggestedLevel: D3D12_VIDEO_ENCODER_LEVEL_SETTING,
    pub pResolutionDependentSupport: *mut D3D12_FEATURE_DATA_VIDEO_ENCODER_RESOLUTION_SUPPORT_LIMITS,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_ENCODER_SUPPORT {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_ENCODER_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
pub struct D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMANDS {
    pub NodeIndex: u32,
    pub CommandCount: u32,
    pub pCommandInfos: *mut D3D12_VIDEO_EXTENSION_COMMAND_INFO,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMANDS {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMANDS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_COUNT {
    pub NodeIndex: u32,
    pub CommandCount: u32,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_COUNT {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_COUNT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_PARAMETERS {
    pub CommandId: ::windows_sys::core::GUID,
    pub Stage: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE,
    pub ParameterCount: u32,
    pub pParameterInfos: *mut D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_INFO,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_PARAMETERS {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_PARAMETERS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_PARAMETER_COUNT {
    pub CommandId: ::windows_sys::core::GUID,
    pub Stage: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE,
    pub ParameterCount: u32,
    pub ParameterPacking: u32,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_PARAMETER_COUNT {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_PARAMETER_COUNT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_SIZE {
    pub NodeIndex: u32,
    pub CommandId: ::windows_sys::core::GUID,
    pub pCreationParameters: *mut ::core::ffi::c_void,
    pub CreationParametersSizeInBytes: usize,
    pub MemoryPoolL0Size: u64,
    pub MemoryPoolL1Size: u64,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_SIZE {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_SIZE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_SUPPORT {
    pub NodeIndex: u32,
    pub CommandId: ::windows_sys::core::GUID,
    pub pInputData: *mut ::core::ffi::c_void,
    pub InputDataSizeInBytes: usize,
    pub pOutputData: *mut ::core::ffi::c_void,
    pub OutputDataSizeInBytes: usize,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_SUPPORT {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_EXTENSION_COMMAND_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_FEATURE_DATA_VIDEO_FEATURE_AREA_SUPPORT {
    pub NodeIndex: u32,
    pub VideoDecodeSupport: super::super::Foundation::BOOL,
    pub VideoProcessSupport: super::super::Foundation::BOOL,
    pub VideoEncodeSupport: super::super::Foundation::BOOL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_FEATURE_AREA_SUPPORT {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_FEATURE_AREA_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_FEATURE_DATA_VIDEO_MOTION_ESTIMATOR {
    pub NodeIndex: u32,
    pub InputFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub BlockSizeFlags: D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_FLAGS,
    pub PrecisionFlags: D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION_FLAGS,
    pub SizeRange: D3D12_VIDEO_SIZE_RANGE,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_MOTION_ESTIMATOR {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_MOTION_ESTIMATOR {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_MOTION_ESTIMATOR_PROTECTED_RESOURCES {
    pub NodeIndex: u32,
    pub SupportFlags: D3D12_VIDEO_PROTECTED_RESOURCE_SUPPORT_FLAGS,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_MOTION_ESTIMATOR_PROTECTED_RESOURCES {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_MOTION_ESTIMATOR_PROTECTED_RESOURCES {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_FEATURE_DATA_VIDEO_MOTION_ESTIMATOR_SIZE {
    pub NodeIndex: u32,
    pub InputFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub BlockSize: D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE,
    pub Precision: D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION,
    pub SizeRange: D3D12_VIDEO_SIZE_RANGE,
    pub Protected: super::super::Foundation::BOOL,
    pub MotionVectorHeapMemoryPoolL0Size: u64,
    pub MotionVectorHeapMemoryPoolL1Size: u64,
    pub MotionEstimatorMemoryPoolL0Size: u64,
    pub MotionEstimatorMemoryPoolL1Size: u64,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_MOTION_ESTIMATOR_SIZE {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_MOTION_ESTIMATOR_SIZE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_FEATURE_DATA_VIDEO_PROCESSOR_SIZE {
    pub NodeMask: u32,
    pub pOutputStreamDesc: *mut D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC,
    pub NumInputStreamDescs: u32,
    pub pInputStreamDescs: *mut D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC,
    pub MemoryPoolL0Size: u64,
    pub MemoryPoolL1Size: u64,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_PROCESSOR_SIZE {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_PROCESSOR_SIZE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_FEATURE_DATA_VIDEO_PROCESSOR_SIZE1 {
    pub NodeMask: u32,
    pub pOutputStreamDesc: *mut D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC,
    pub NumInputStreamDescs: u32,
    pub pInputStreamDescs: *mut D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC,
    pub Protected: super::super::Foundation::BOOL,
    pub MemoryPoolL0Size: u64,
    pub MemoryPoolL1Size: u64,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_PROCESSOR_SIZE1 {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_PROCESSOR_SIZE1 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_PROCESS_MAX_INPUT_STREAMS {
    pub NodeIndex: u32,
    pub MaxInputStreams: u32,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_PROCESS_MAX_INPUT_STREAMS {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_PROCESS_MAX_INPUT_STREAMS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_FEATURE_DATA_VIDEO_PROCESS_PROTECTED_RESOURCES {
    pub NodeIndex: u32,
    pub SupportFlags: D3D12_VIDEO_PROTECTED_RESOURCE_SUPPORT_FLAGS,
}
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_PROCESS_PROTECTED_RESOURCES {}
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_PROCESS_PROTECTED_RESOURCES {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_FEATURE_DATA_VIDEO_PROCESS_REFERENCE_INFO {
    pub NodeIndex: u32,
    pub DeinterlaceMode: D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS,
    pub Filters: D3D12_VIDEO_PROCESS_FILTER_FLAGS,
    pub FeatureSupport: D3D12_VIDEO_PROCESS_FEATURE_FLAGS,
    pub InputFrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub OutputFrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub EnableAutoProcessing: super::super::Foundation::BOOL,
    pub PastFrames: u32,
    pub FutureFrames: u32,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_PROCESS_REFERENCE_INFO {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_PROCESS_REFERENCE_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_FEATURE_DATA_VIDEO_PROCESS_SUPPORT {
    pub NodeIndex: u32,
    pub InputSample: D3D12_VIDEO_SAMPLE,
    pub InputFieldType: D3D12_VIDEO_FIELD_TYPE,
    pub InputStereoFormat: D3D12_VIDEO_FRAME_STEREO_FORMAT,
    pub InputFrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub OutputFormat: D3D12_VIDEO_FORMAT,
    pub OutputStereoFormat: D3D12_VIDEO_FRAME_STEREO_FORMAT,
    pub OutputFrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub SupportFlags: D3D12_VIDEO_PROCESS_SUPPORT_FLAGS,
    pub ScaleSupport: D3D12_VIDEO_SCALE_SUPPORT,
    pub FeatureSupport: D3D12_VIDEO_PROCESS_FEATURE_FLAGS,
    pub DeinterlaceSupport: D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS,
    pub AutoProcessingSupport: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS,
    pub FilterSupport: D3D12_VIDEO_PROCESS_FILTER_FLAGS,
    pub FilterRangeSupport: [D3D12_VIDEO_PROCESS_FILTER_RANGE; 32],
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_FEATURE_DATA_VIDEO_PROCESS_SUPPORT {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_FEATURE_DATA_VIDEO_PROCESS_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_FEATURE_VIDEO = i32;
pub const D3D12_FEATURE_VIDEO_DECODE_SUPPORT: D3D12_FEATURE_VIDEO = 0i32;
pub const D3D12_FEATURE_VIDEO_DECODE_PROFILES: D3D12_FEATURE_VIDEO = 1i32;
pub const D3D12_FEATURE_VIDEO_DECODE_FORMATS: D3D12_FEATURE_VIDEO = 2i32;
pub const D3D12_FEATURE_VIDEO_DECODE_CONVERSION_SUPPORT: D3D12_FEATURE_VIDEO = 3i32;
pub const D3D12_FEATURE_VIDEO_PROCESS_SUPPORT: D3D12_FEATURE_VIDEO = 5i32;
pub const D3D12_FEATURE_VIDEO_PROCESS_MAX_INPUT_STREAMS: D3D12_FEATURE_VIDEO = 6i32;
pub const D3D12_FEATURE_VIDEO_PROCESS_REFERENCE_INFO: D3D12_FEATURE_VIDEO = 7i32;
pub const D3D12_FEATURE_VIDEO_DECODER_HEAP_SIZE: D3D12_FEATURE_VIDEO = 8i32;
pub const D3D12_FEATURE_VIDEO_PROCESSOR_SIZE: D3D12_FEATURE_VIDEO = 9i32;
pub const D3D12_FEATURE_VIDEO_DECODE_PROFILE_COUNT: D3D12_FEATURE_VIDEO = 10i32;
pub const D3D12_FEATURE_VIDEO_DECODE_FORMAT_COUNT: D3D12_FEATURE_VIDEO = 11i32;
pub const D3D12_FEATURE_VIDEO_ARCHITECTURE: D3D12_FEATURE_VIDEO = 17i32;
pub const D3D12_FEATURE_VIDEO_DECODE_HISTOGRAM: D3D12_FEATURE_VIDEO = 18i32;
pub const D3D12_FEATURE_VIDEO_FEATURE_AREA_SUPPORT: D3D12_FEATURE_VIDEO = 19i32;
pub const D3D12_FEATURE_VIDEO_MOTION_ESTIMATOR: D3D12_FEATURE_VIDEO = 20i32;
pub const D3D12_FEATURE_VIDEO_MOTION_ESTIMATOR_SIZE: D3D12_FEATURE_VIDEO = 21i32;
pub const D3D12_FEATURE_VIDEO_EXTENSION_COMMAND_COUNT: D3D12_FEATURE_VIDEO = 22i32;
pub const D3D12_FEATURE_VIDEO_EXTENSION_COMMANDS: D3D12_FEATURE_VIDEO = 23i32;
pub const D3D12_FEATURE_VIDEO_EXTENSION_COMMAND_PARAMETER_COUNT: D3D12_FEATURE_VIDEO = 24i32;
pub const D3D12_FEATURE_VIDEO_EXTENSION_COMMAND_PARAMETERS: D3D12_FEATURE_VIDEO = 25i32;
pub const D3D12_FEATURE_VIDEO_EXTENSION_COMMAND_SUPPORT: D3D12_FEATURE_VIDEO = 26i32;
pub const D3D12_FEATURE_VIDEO_EXTENSION_COMMAND_SIZE: D3D12_FEATURE_VIDEO = 27i32;
pub const D3D12_FEATURE_VIDEO_DECODE_PROTECTED_RESOURCES: D3D12_FEATURE_VIDEO = 28i32;
pub const D3D12_FEATURE_VIDEO_PROCESS_PROTECTED_RESOURCES: D3D12_FEATURE_VIDEO = 29i32;
pub const D3D12_FEATURE_VIDEO_MOTION_ESTIMATOR_PROTECTED_RESOURCES: D3D12_FEATURE_VIDEO = 30i32;
pub const D3D12_FEATURE_VIDEO_DECODER_HEAP_SIZE1: D3D12_FEATURE_VIDEO = 31i32;
pub const D3D12_FEATURE_VIDEO_PROCESSOR_SIZE1: D3D12_FEATURE_VIDEO = 32i32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_QUERY_DATA_VIDEO_DECODE_STATISTICS {
    pub Status: u64,
    pub NumMacroblocksAffected: u64,
    pub FrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub BitRate: u32,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_QUERY_DATA_VIDEO_DECODE_STATISTICS {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_QUERY_DATA_VIDEO_DECODE_STATISTICS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_RESOLVE_VIDEO_MOTION_VECTOR_HEAP_INPUT {
    pub pMotionVectorHeap: ID3D12VideoMotionVectorHeap,
    pub PixelWidth: u32,
    pub PixelHeight: u32,
}
impl ::core::marker::Copy for D3D12_RESOLVE_VIDEO_MOTION_VECTOR_HEAP_INPUT {}
impl ::core::clone::Clone for D3D12_RESOLVE_VIDEO_MOTION_VECTOR_HEAP_INPUT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_RESOLVE_VIDEO_MOTION_VECTOR_HEAP_OUTPUT {
    pub pMotionVectorTexture2D: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub MotionVectorCoordinate: D3D12_RESOURCE_COORDINATE,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_RESOLVE_VIDEO_MOTION_VECTOR_HEAP_OUTPUT {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_RESOLVE_VIDEO_MOTION_VECTOR_HEAP_OUTPUT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_RESOURCE_COORDINATE {
    pub X: u64,
    pub Y: u32,
    pub Z: u32,
    pub SubresourceIndex: u32,
}
impl ::core::marker::Copy for D3D12_RESOURCE_COORDINATE {}
impl ::core::clone::Clone for D3D12_RESOURCE_COORDINATE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_DECODER_DESC {
    pub NodeMask: u32,
    pub Configuration: D3D12_VIDEO_DECODE_CONFIGURATION,
}
impl ::core::marker::Copy for D3D12_VIDEO_DECODER_DESC {}
impl ::core::clone::Clone for D3D12_VIDEO_DECODER_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_VIDEO_DECODER_HEAP_DESC {
    pub NodeMask: u32,
    pub Configuration: D3D12_VIDEO_DECODE_CONFIGURATION,
    pub DecodeWidth: u32,
    pub DecodeHeight: u32,
    pub Format: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub FrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub BitRate: u32,
    pub MaxDecodePictureBufferCount: u32,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_VIDEO_DECODER_HEAP_DESC {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_VIDEO_DECODER_HEAP_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_DECODE_ARGUMENT_TYPE = i32;
pub const D3D12_VIDEO_DECODE_ARGUMENT_TYPE_PICTURE_PARAMETERS: D3D12_VIDEO_DECODE_ARGUMENT_TYPE = 0i32;
pub const D3D12_VIDEO_DECODE_ARGUMENT_TYPE_INVERSE_QUANTIZATION_MATRIX: D3D12_VIDEO_DECODE_ARGUMENT_TYPE = 1i32;
pub const D3D12_VIDEO_DECODE_ARGUMENT_TYPE_SLICE_CONTROL: D3D12_VIDEO_DECODE_ARGUMENT_TYPE = 2i32;
pub const D3D12_VIDEO_DECODE_ARGUMENT_TYPE_MAX_VALID: D3D12_VIDEO_DECODE_ARGUMENT_TYPE = 3i32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_DECODE_COMPRESSED_BITSTREAM {
    pub pBuffer: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub Offset: u64,
    pub Size: u64,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_COMPRESSED_BITSTREAM {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_COMPRESSED_BITSTREAM {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_DECODE_CONFIGURATION {
    pub DecodeProfile: ::windows_sys::core::GUID,
    pub BitstreamEncryption: D3D12_BITSTREAM_ENCRYPTION_TYPE,
    pub InterlaceType: D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE,
}
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_CONFIGURATION {}
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_CONFIGURATION {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS = u32;
pub const D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_NONE: D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS = 0u32;
pub const D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_HEIGHT_ALIGNMENT_MULTIPLE_32_REQUIRED: D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS = 1u32;
pub const D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_POST_PROCESSING_SUPPORTED: D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS = 2u32;
pub const D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_REFERENCE_ONLY_ALLOCATIONS_REQUIRED: D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS = 4u32;
pub const D3D12_VIDEO_DECODE_CONFIGURATION_FLAG_ALLOW_RESOLUTION_CHANGE_ON_NON_KEY_FRAME: D3D12_VIDEO_DECODE_CONFIGURATION_FLAGS = 8u32;
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS {
    pub Enable: super::super::Foundation::BOOL,
    pub pReferenceTexture2D: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub ReferenceSubresource: u32,
    pub OutputColorSpace: super::super::Graphics::Dxgi::Common::DXGI_COLOR_SPACE_TYPE,
    pub DecodeColorSpace: super::super::Graphics::Dxgi::Common::DXGI_COLOR_SPACE_TYPE,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS1 {
    pub Enable: super::super::Foundation::BOOL,
    pub pReferenceTexture2D: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub ReferenceSubresource: u32,
    pub OutputColorSpace: super::super::Graphics::Dxgi::Common::DXGI_COLOR_SPACE_TYPE,
    pub DecodeColorSpace: super::super::Graphics::Dxgi::Common::DXGI_COLOR_SPACE_TYPE,
    pub OutputWidth: u32,
    pub OutputHeight: u32,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS1 {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS1 {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_DECODE_CONVERSION_SUPPORT_FLAGS = u32;
pub const D3D12_VIDEO_DECODE_CONVERSION_SUPPORT_FLAG_NONE: D3D12_VIDEO_DECODE_CONVERSION_SUPPORT_FLAGS = 0u32;
pub const D3D12_VIDEO_DECODE_CONVERSION_SUPPORT_FLAG_SUPPORTED: D3D12_VIDEO_DECODE_CONVERSION_SUPPORT_FLAGS = 1u32;
#[repr(C)]
pub struct D3D12_VIDEO_DECODE_FRAME_ARGUMENT {
    pub Type: D3D12_VIDEO_DECODE_ARGUMENT_TYPE,
    pub Size: u32,
    pub pData: *mut ::core::ffi::c_void,
}
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_FRAME_ARGUMENT {}
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_FRAME_ARGUMENT {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT = i32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_Y: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT = 0i32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_U: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT = 1i32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_V: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT = 2i32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_R: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT = 0i32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_G: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT = 1i32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_B: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT = 2i32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_A: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT = 3i32;
pub type D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS = u32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAG_NONE: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS = 0u32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAG_Y: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS = 1u32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAG_U: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS = 2u32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAG_V: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS = 4u32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAG_R: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS = 1u32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAG_G: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS = 2u32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAG_B: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS = 4u32;
pub const D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAG_A: D3D12_VIDEO_DECODE_HISTOGRAM_COMPONENT_FLAGS = 8u32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_DECODE_INPUT_STREAM_ARGUMENTS {
    pub NumFrameArguments: u32,
    pub FrameArguments: [D3D12_VIDEO_DECODE_FRAME_ARGUMENT; 10],
    pub ReferenceFrames: D3D12_VIDEO_DECODE_REFERENCE_FRAMES,
    pub CompressedBitstream: D3D12_VIDEO_DECODE_COMPRESSED_BITSTREAM,
    pub pHeap: ID3D12VideoDecoderHeap,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_INPUT_STREAM_ARGUMENTS {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_INPUT_STREAM_ARGUMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_DECODE_OUTPUT_HISTOGRAM {
    pub Offset: u64,
    pub pBuffer: super::super::Graphics::Direct3D12::ID3D12Resource,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_OUTPUT_HISTOGRAM {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_OUTPUT_HISTOGRAM {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_VIDEO_DECODE_OUTPUT_STREAM_ARGUMENTS {
    pub pOutputTexture2D: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub OutputSubresource: u32,
    pub ConversionArguments: D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_OUTPUT_STREAM_ARGUMENTS {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_OUTPUT_STREAM_ARGUMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_VIDEO_DECODE_OUTPUT_STREAM_ARGUMENTS1 {
    pub pOutputTexture2D: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub OutputSubresource: u32,
    pub ConversionArguments: D3D12_VIDEO_DECODE_CONVERSION_ARGUMENTS1,
    pub Histograms: [D3D12_VIDEO_DECODE_OUTPUT_HISTOGRAM; 4],
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_OUTPUT_STREAM_ARGUMENTS1 {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_OUTPUT_STREAM_ARGUMENTS1 {
    fn clone(&self) -> Self {
        *self
    }
}
pub const D3D12_VIDEO_DECODE_PROFILE_AV1_12BIT_PROFILE2: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 387084297,
    data2: 40975,
    data3: 19681,
    data4: [153, 78, 191, 64, 129, 246, 243, 240],
};
pub const D3D12_VIDEO_DECODE_PROFILE_AV1_12BIT_PROFILE2_420: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 763412182,
    data2: 40108,
    data3: 18485,
    data4: [158, 145, 50, 123, 188, 79, 158, 232],
};
pub const D3D12_VIDEO_DECODE_PROFILE_AV1_PROFILE0: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3099479243,
    data2: 53075,
    data3: 18106,
    data4: [141, 89, 214, 184, 166, 218, 93, 42],
};
pub const D3D12_VIDEO_DECODE_PROFILE_AV1_PROFILE1: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1765211919,
    data2: 17841,
    data3: 16739,
    data4: [156, 193, 100, 110, 246, 148, 97, 8],
};
pub const D3D12_VIDEO_DECODE_PROFILE_AV1_PROFILE2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 207563425, data2: 58689, data3: 16521, data4: [187, 123, 152, 17, 10, 25, 215, 200] };
pub const D3D12_VIDEO_DECODE_PROFILE_H264: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487720, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const D3D12_VIDEO_DECODE_PROFILE_H264_MULTIVIEW: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1885052290,
    data2: 30415,
    data3: 18902,
    data4: [183, 230, 172, 136, 114, 219, 1, 60],
};
pub const D3D12_VIDEO_DECODE_PROFILE_H264_STEREO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4188720315, data2: 49846, data3: 19708, data4: [135, 121, 87, 7, 177, 118, 5, 82] };
pub const D3D12_VIDEO_DECODE_PROFILE_H264_STEREO_PROGRESSIVE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3617319130, data2: 3313, data3: 19585, data4: [184, 42, 105, 164, 226, 54, 244, 61] };
pub const D3D12_VIDEO_DECODE_PROFILE_HEVC_MAIN: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1527895323, data2: 12108, data3: 17490, data4: [188, 195, 9, 242, 161, 22, 12, 192] };
pub const D3D12_VIDEO_DECODE_PROFILE_HEVC_MAIN10: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 276492512, data2: 61210, data3: 19737, data4: [171, 168, 103, 161, 99, 7, 61, 19] };
pub const D3D12_VIDEO_DECODE_PROFILE_MPEG1_AND_MPEG2: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2255052562,
    data2: 13326,
    data3: 20228,
    data4: [159, 211, 146, 83, 221, 50, 116, 96],
};
pub const D3D12_VIDEO_DECODE_PROFILE_MPEG2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3995550079, data2: 24104, data3: 20069, data4: [190, 234, 29, 38, 181, 8, 173, 201] };
pub const D3D12_VIDEO_DECODE_PROFILE_MPEG4PT2_ADVSIMPLE_NOGMC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3980495519, data2: 269, data3: 20186, data4: [154, 227, 154, 101, 53, 141, 141, 46] };
pub const D3D12_VIDEO_DECODE_PROFILE_MPEG4PT2_SIMPLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4023799156,
    data2: 51688,
    data3: 16855,
    data4: [165, 233, 233, 176, 227, 159, 163, 25],
};
pub const D3D12_VIDEO_DECODE_PROFILE_VC1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487779, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const D3D12_VIDEO_DECODE_PROFILE_VC1_D2010: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487780, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const D3D12_VIDEO_DECODE_PROFILE_VP8: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2428017130,
    data2: 14946,
    data3: 18181,
    data4: [136, 179, 141, 240, 75, 39, 68, 231],
};
pub const D3D12_VIDEO_DECODE_PROFILE_VP9: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1178011640,
    data2: 41424,
    data3: 17797,
    data4: [135, 109, 131, 170, 109, 96, 184, 158],
};
pub const D3D12_VIDEO_DECODE_PROFILE_VP9_10BIT_PROFILE2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2764524015, data2: 28367, data3: 18602, data4: [132, 72, 80, 167, 161, 22, 95, 247] };
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_DECODE_REFERENCE_FRAMES {
    pub NumTexture2Ds: u32,
    pub ppTexture2Ds: *mut super::super::Graphics::Direct3D12::ID3D12Resource,
    pub pSubresources: *mut u32,
    pub ppHeaps: *mut ID3D12VideoDecoderHeap,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_DECODE_REFERENCE_FRAMES {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_DECODE_REFERENCE_FRAMES {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_DECODE_STATUS = i32;
pub const D3D12_VIDEO_DECODE_STATUS_OK: D3D12_VIDEO_DECODE_STATUS = 0i32;
pub const D3D12_VIDEO_DECODE_STATUS_CONTINUE: D3D12_VIDEO_DECODE_STATUS = 1i32;
pub const D3D12_VIDEO_DECODE_STATUS_CONTINUE_SKIP_DISPLAY: D3D12_VIDEO_DECODE_STATUS = 2i32;
pub const D3D12_VIDEO_DECODE_STATUS_RESTART: D3D12_VIDEO_DECODE_STATUS = 3i32;
pub const D3D12_VIDEO_DECODE_STATUS_RATE_EXCEEDED: D3D12_VIDEO_DECODE_STATUS = 4i32;
pub type D3D12_VIDEO_DECODE_SUPPORT_FLAGS = u32;
pub const D3D12_VIDEO_DECODE_SUPPORT_FLAG_NONE: D3D12_VIDEO_DECODE_SUPPORT_FLAGS = 0u32;
pub const D3D12_VIDEO_DECODE_SUPPORT_FLAG_SUPPORTED: D3D12_VIDEO_DECODE_SUPPORT_FLAGS = 1u32;
pub type D3D12_VIDEO_DECODE_TIER = i32;
pub const D3D12_VIDEO_DECODE_TIER_NOT_SUPPORTED: D3D12_VIDEO_DECODE_TIER = 0i32;
pub const D3D12_VIDEO_DECODE_TIER_1: D3D12_VIDEO_DECODE_TIER = 1i32;
pub const D3D12_VIDEO_DECODE_TIER_2: D3D12_VIDEO_DECODE_TIER = 2i32;
pub const D3D12_VIDEO_DECODE_TIER_3: D3D12_VIDEO_DECODE_TIER = 3i32;
pub type D3D12_VIDEO_ENCODER_CODEC = i32;
pub const D3D12_VIDEO_ENCODER_CODEC_H264: D3D12_VIDEO_ENCODER_CODEC = 0i32;
pub const D3D12_VIDEO_ENCODER_CODEC_HEVC: D3D12_VIDEO_ENCODER_CODEC = 1i32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION {
    pub DataSize: u32,
    pub Anonymous: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_0,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_0 {
    pub pH264Config: *mut D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264,
    pub pHEVCConfig: *mut D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_0 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264 {
    pub ConfigurationFlags: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAGS,
    pub DirectModeConfig: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_DIRECT_MODES,
    pub DisableDeblockingFilterConfig: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODES,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264 {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_DIRECT_MODES = i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_DIRECT_MODES_DISABLED: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_DIRECT_MODES = 0i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_DIRECT_MODES_TEMPORAL: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_DIRECT_MODES = 1i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_DIRECT_MODES_SPATIAL: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_DIRECT_MODES = 2i32;
pub type D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAG_NONE: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAG_USE_CONSTRAINED_INTRAPREDICTION: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAG_USE_ADAPTIVE_8x8_TRANSFORM: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAGS = 2u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAG_ENABLE_CABAC_ENCODING: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAGS = 4u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAG_ALLOW_REQUEST_INTRA_CONSTRAINED_SLICES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_FLAGS = 8u32;
pub type D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODES = i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_0_ALL_LUMA_CHROMA_SLICE_BLOCK_EDGES_ALWAYS_FILTERED: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODES = 0i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_1_DISABLE_ALL_SLICE_BLOCK_EDGES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODES = 1i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_2_DISABLE_SLICE_BOUNDARIES_BLOCKS: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODES = 2i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_3_USE_TWO_STAGE_DEBLOCKING: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODES = 3i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_4_DISABLE_CHROMA_BLOCK_EDGES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODES = 4i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_5_DISABLE_CHROMA_BLOCK_EDGES_AND_LUMA_BOUNDARIES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODES = 5i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_6_DISABLE_CHROMA_BLOCK_EDGES_AND_USE_LUMA_TWO_STAGE_DEBLOCKING: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODES = 6i32;
pub type D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAG_NONE: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAG_0_ALL_LUMA_CHROMA_SLICE_BLOCK_EDGES_ALWAYS_FILTERED: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAG_1_DISABLE_ALL_SLICE_BLOCK_EDGES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS = 2u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAG_2_DISABLE_SLICE_BOUNDARIES_BLOCKS: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS = 4u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAG_3_USE_TWO_STAGE_DEBLOCKING: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS = 8u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAG_4_DISABLE_CHROMA_BLOCK_EDGES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS = 16u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAG_5_DISABLE_CHROMA_BLOCK_EDGES_AND_LUMA_BOUNDARIES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS = 32u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAG_6_DISABLE_CHROMA_BLOCK_EDGES_AND_USE_LUMA_TWO_STAGE_DEBLOCKING: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS = 64u32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC {
    pub ConfigurationFlags: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS,
    pub MinLumaCodingUnitSize: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE,
    pub MaxLumaCodingUnitSize: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE,
    pub MinLumaTransformUnitSize: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE,
    pub MaxLumaTransformUnitSize: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE,
    pub max_transform_hierarchy_depth_inter: u8,
    pub max_transform_hierarchy_depth_intra: u8,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE = i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE_8x8: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE = 0i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE_16x16: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE = 1i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE_32x32: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE = 2i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE_64x64: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE = 3i32;
pub type D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAG_NONE: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAG_DISABLE_LOOP_FILTER_ACROSS_SLICES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAG_ALLOW_REQUEST_INTRA_CONSTRAINED_SLICES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS = 2u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAG_ENABLE_SAO_FILTER: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS = 4u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAG_ENABLE_LONG_TERM_REFERENCES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS = 8u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAG_USE_ASYMETRIC_MOTION_PARTITION: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS = 16u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAG_ENABLE_TRANSFORM_SKIPPING: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS = 32u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAG_USE_CONSTRAINED_INTRAPREDICTION: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_FLAGS = 64u32;
pub type D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE = i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE_4x4: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE = 0i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE_8x8: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE = 1i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE_16x16: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE = 2i32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE_32x32: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE = 3i32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT {
    pub DataSize: u32,
    pub Anonymous: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_0,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_0 {
    pub pH264Support: *mut D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264,
    pub pHEVCSupport: *mut D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_0 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264 {
    pub SupportFlags: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS,
    pub DisableDeblockingFilterSupportedModes: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_H264_SLICES_DEBLOCKING_MODE_FLAGS,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264 {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAG_NONE: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAG_CABAC_ENCODING_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAG_INTRA_SLICE_CONSTRAINED_ENCODING_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS = 2u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAG_BFRAME_LTR_COMBINED_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS = 4u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAG_ADAPTIVE_8x8_TRANSFORM_ENCODING_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS = 8u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAG_DIRECT_SPATIAL_ENCODING_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS = 16u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAG_DIRECT_TEMPORAL_ENCODING_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS = 32u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAG_CONSTRAINED_INTRAPREDICTION_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_H264_FLAGS = 64u32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC {
    pub SupportFlags: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS,
    pub MinLumaCodingUnitSize: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE,
    pub MaxLumaCodingUnitSize: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_CUSIZE,
    pub MinLumaTransformUnitSize: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE,
    pub MaxLumaTransformUnitSize: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_HEVC_TUSIZE,
    pub max_transform_hierarchy_depth_inter: u8,
    pub max_transform_hierarchy_depth_intra: u8,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_NONE: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_BFRAME_LTR_COMBINED_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_INTRA_SLICE_CONSTRAINED_ENCODING_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 2u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_CONSTRAINED_INTRAPREDICTION_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 4u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_SAO_FILTER_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 8u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_ASYMETRIC_MOTION_PARTITION_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 16u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_ASYMETRIC_MOTION_PARTITION_REQUIRED: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 32u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_TRANSFORM_SKIP_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 64u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_DISABLING_LOOP_FILTER_ACROSS_SLICES_SUPPORT: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 128u32;
pub const D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAG_P_FRAMES_IMPLEMENTED_AS_LOW_DELAY_B_FRAMES: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION_SUPPORT_HEVC_FLAGS = 256u32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT {
    pub DataSize: u32,
    pub Anonymous: D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_0,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_0 {
    pub pH264Support: *mut D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_H264,
    pub pHEVCSupport: *mut D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_HEVC,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_0 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_H264 {
    pub MaxL0ReferencesForP: u32,
    pub MaxL0ReferencesForB: u32,
    pub MaxL1ReferencesForB: u32,
    pub MaxLongTermReferences: u32,
    pub MaxDPBCapacity: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_H264 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_H264 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_HEVC {
    pub MaxL0ReferencesForP: u32,
    pub MaxL0ReferencesForB: u32,
    pub MaxL1ReferencesForB: u32,
    pub MaxLongTermReferences: u32,
    pub MaxDPBCapacity: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_HEVC {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_CODEC_PICTURE_CONTROL_SUPPORT_HEVC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_ENCODER_COMPRESSED_BITSTREAM {
    pub pBuffer: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub FrameStartOffset: u64,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_COMPRESSED_BITSTREAM {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_COMPRESSED_BITSTREAM {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_VIDEO_ENCODER_DESC {
    pub NodeMask: u32,
    pub Flags: D3D12_VIDEO_ENCODER_FLAGS,
    pub EncodeCodec: D3D12_VIDEO_ENCODER_CODEC,
    pub EncodeProfile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub InputFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub CodecConfiguration: D3D12_VIDEO_ENCODER_CODEC_CONFIGURATION,
    pub MaxMotionEstimationPrecision: D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_DESC {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_VIDEO_ENCODER_ENCODEFRAME_INPUT_ARGUMENTS {
    pub SequenceControlDesc: D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_DESC,
    pub PictureControlDesc: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_DESC,
    pub pInputFrame: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub InputFrameSubresource: u32,
    pub CurrentFrameBitstreamMetadataSize: u32,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_ENCODEFRAME_INPUT_ARGUMENTS {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_ENCODEFRAME_INPUT_ARGUMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_ENCODER_ENCODEFRAME_OUTPUT_ARGUMENTS {
    pub Bitstream: D3D12_VIDEO_ENCODER_COMPRESSED_BITSTREAM,
    pub ReconstructedPicture: D3D12_VIDEO_ENCODER_RECONSTRUCTED_PICTURE,
    pub EncoderOutputMetadata: D3D12_VIDEO_ENCODER_ENCODE_OPERATION_METADATA_BUFFER,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_ENCODEFRAME_OUTPUT_ARGUMENTS {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_ENCODEFRAME_OUTPUT_ARGUMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAG_NO_ERROR: D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAG_CODEC_PICTURE_CONTROL_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAG_SUBREGION_LAYOUT_CONFIGURATION_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAGS = 2u32;
pub const D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAG_INVALID_REFERENCE_PICTURES: D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAGS = 4u32;
pub const D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAG_RECONFIGURATION_REQUEST_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAGS = 8u32;
pub const D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAG_INVALID_METADATA_BUFFER_SOURCE: D3D12_VIDEO_ENCODER_ENCODE_ERROR_FLAGS = 16u32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_ENCODER_ENCODE_OPERATION_METADATA_BUFFER {
    pub pBuffer: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub Offset: u64,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_ENCODE_OPERATION_METADATA_BUFFER {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_ENCODE_OPERATION_METADATA_BUFFER {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_FLAG_NONE: D3D12_VIDEO_ENCODER_FLAGS = 0u32;
pub type D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE = i32;
pub const D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE_FULL_FRAME: D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE = 0i32;
pub const D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE_BYTES_PER_SUBREGION: D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE = 1i32;
pub const D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE_SQUARE_UNITS_PER_SUBREGION_ROW_UNALIGNED: D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE = 2i32;
pub const D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE_UNIFORM_PARTITIONING_ROWS_PER_SUBREGION: D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE = 3i32;
pub const D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE_UNIFORM_PARTITIONING_SUBREGIONS_PER_FRAME: D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE = 4i32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_FRAME_SUBREGION_METADATA {
    pub bSize: u64,
    pub bStartOffset: u64,
    pub bHeaderSize: u64,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_FRAME_SUBREGION_METADATA {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_FRAME_SUBREGION_METADATA {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_FRAME_TYPE_H264 = i32;
pub const D3D12_VIDEO_ENCODER_FRAME_TYPE_H264_I_FRAME: D3D12_VIDEO_ENCODER_FRAME_TYPE_H264 = 0i32;
pub const D3D12_VIDEO_ENCODER_FRAME_TYPE_H264_P_FRAME: D3D12_VIDEO_ENCODER_FRAME_TYPE_H264 = 1i32;
pub const D3D12_VIDEO_ENCODER_FRAME_TYPE_H264_B_FRAME: D3D12_VIDEO_ENCODER_FRAME_TYPE_H264 = 2i32;
pub const D3D12_VIDEO_ENCODER_FRAME_TYPE_H264_IDR_FRAME: D3D12_VIDEO_ENCODER_FRAME_TYPE_H264 = 3i32;
pub type D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC = i32;
pub const D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC_I_FRAME: D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC = 0i32;
pub const D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC_P_FRAME: D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC = 1i32;
pub const D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC_B_FRAME: D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC = 2i32;
pub const D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC_IDR_FRAME: D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC = 3i32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_HEAP_DESC {
    pub NodeMask: u32,
    pub Flags: D3D12_VIDEO_ENCODER_HEAP_FLAGS,
    pub EncodeCodec: D3D12_VIDEO_ENCODER_CODEC,
    pub EncodeProfile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub EncodeLevel: D3D12_VIDEO_ENCODER_LEVEL_SETTING,
    pub ResolutionsListCount: u32,
    pub pResolutionList: *mut D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_HEAP_DESC {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_HEAP_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_HEAP_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_HEAP_FLAG_NONE: D3D12_VIDEO_ENCODER_HEAP_FLAGS = 0u32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_INTRA_REFRESH {
    pub Mode: D3D12_VIDEO_ENCODER_INTRA_REFRESH_MODE,
    pub IntraRefreshDuration: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_INTRA_REFRESH {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_INTRA_REFRESH {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_INTRA_REFRESH_MODE = i32;
pub const D3D12_VIDEO_ENCODER_INTRA_REFRESH_MODE_NONE: D3D12_VIDEO_ENCODER_INTRA_REFRESH_MODE = 0i32;
pub const D3D12_VIDEO_ENCODER_INTRA_REFRESH_MODE_ROW_BASED: D3D12_VIDEO_ENCODER_INTRA_REFRESH_MODE = 1i32;
pub type D3D12_VIDEO_ENCODER_LEVELS_H264 = i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_1: D3D12_VIDEO_ENCODER_LEVELS_H264 = 0i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_1b: D3D12_VIDEO_ENCODER_LEVELS_H264 = 1i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_11: D3D12_VIDEO_ENCODER_LEVELS_H264 = 2i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_12: D3D12_VIDEO_ENCODER_LEVELS_H264 = 3i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_13: D3D12_VIDEO_ENCODER_LEVELS_H264 = 4i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_2: D3D12_VIDEO_ENCODER_LEVELS_H264 = 5i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_21: D3D12_VIDEO_ENCODER_LEVELS_H264 = 6i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_22: D3D12_VIDEO_ENCODER_LEVELS_H264 = 7i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_3: D3D12_VIDEO_ENCODER_LEVELS_H264 = 8i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_31: D3D12_VIDEO_ENCODER_LEVELS_H264 = 9i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_32: D3D12_VIDEO_ENCODER_LEVELS_H264 = 10i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_4: D3D12_VIDEO_ENCODER_LEVELS_H264 = 11i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_41: D3D12_VIDEO_ENCODER_LEVELS_H264 = 12i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_42: D3D12_VIDEO_ENCODER_LEVELS_H264 = 13i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_5: D3D12_VIDEO_ENCODER_LEVELS_H264 = 14i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_51: D3D12_VIDEO_ENCODER_LEVELS_H264 = 15i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_52: D3D12_VIDEO_ENCODER_LEVELS_H264 = 16i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_6: D3D12_VIDEO_ENCODER_LEVELS_H264 = 17i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_61: D3D12_VIDEO_ENCODER_LEVELS_H264 = 18i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_H264_62: D3D12_VIDEO_ENCODER_LEVELS_H264 = 19i32;
pub type D3D12_VIDEO_ENCODER_LEVELS_HEVC = i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_1: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 0i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_2: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 1i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_21: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 2i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_3: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 3i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_31: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 4i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_4: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 5i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_41: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 6i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_5: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 7i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_51: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 8i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_52: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 9i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_6: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 10i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_61: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 11i32;
pub const D3D12_VIDEO_ENCODER_LEVELS_HEVC_62: D3D12_VIDEO_ENCODER_LEVELS_HEVC = 12i32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_LEVEL_SETTING {
    pub DataSize: u32,
    pub Anonymous: D3D12_VIDEO_ENCODER_LEVEL_SETTING_0,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_LEVEL_SETTING {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_LEVEL_SETTING {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union D3D12_VIDEO_ENCODER_LEVEL_SETTING_0 {
    pub pH264LevelSetting: *mut D3D12_VIDEO_ENCODER_LEVELS_H264,
    pub pHEVCLevelSetting: *mut D3D12_VIDEO_ENCODER_LEVEL_TIER_CONSTRAINTS_HEVC,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_LEVEL_SETTING_0 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_LEVEL_SETTING_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_LEVEL_TIER_CONSTRAINTS_HEVC {
    pub Level: D3D12_VIDEO_ENCODER_LEVELS_HEVC,
    pub Tier: D3D12_VIDEO_ENCODER_TIER_HEVC,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_LEVEL_TIER_CONSTRAINTS_HEVC {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_LEVEL_TIER_CONSTRAINTS_HEVC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE = i32;
pub const D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE_MAXIMUM: D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE = 0i32;
pub const D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE_FULL_PIXEL: D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE = 1i32;
pub const D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE_HALF_PIXEL: D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE = 2i32;
pub const D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE_QUARTER_PIXEL: D3D12_VIDEO_ENCODER_MOTION_ESTIMATION_PRECISION_MODE = 3i32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_OUTPUT_METADATA {
    pub EncodeErrorFlags: u64,
    pub EncodeStats: D3D12_VIDEO_ENCODER_OUTPUT_METADATA_STATISTICS,
    pub EncodedBitstreamWrittenBytesCount: u64,
    pub WrittenSubregionsCount: u64,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_OUTPUT_METADATA {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_OUTPUT_METADATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_OUTPUT_METADATA_STATISTICS {
    pub AverageQP: u64,
    pub IntraCodingUnitsCount: u64,
    pub InterCodingUnitsCount: u64,
    pub SkipCodingUnitsCount: u64,
    pub AverageMotionEstimationXDirection: u64,
    pub AverageMotionEstimationYDirection: u64,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_OUTPUT_METADATA_STATISTICS {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_OUTPUT_METADATA_STATISTICS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA {
    pub DataSize: u32,
    pub Anonymous: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_0,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub union D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_0 {
    pub pH264PicData: *mut D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264,
    pub pHEVCPicData: *mut D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_0 {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264 {
    pub Flags: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_FLAGS,
    pub FrameType: D3D12_VIDEO_ENCODER_FRAME_TYPE_H264,
    pub pic_parameter_set_id: u32,
    pub idr_pic_id: u32,
    pub PictureOrderCountNumber: u32,
    pub FrameDecodingOrderNumber: u32,
    pub TemporalLayerIndex: u32,
    pub List0ReferenceFramesCount: u32,
    pub pList0ReferenceFrames: *mut u32,
    pub List1ReferenceFramesCount: u32,
    pub pList1ReferenceFrames: *mut u32,
    pub ReferenceFramesReconPictureDescriptorsCount: u32,
    pub pReferenceFramesReconPictureDescriptors: *mut D3D12_VIDEO_ENCODER_REFERENCE_PICTURE_DESCRIPTOR_H264,
    pub adaptive_ref_pic_marking_mode_flag: u8,
    pub RefPicMarkingOperationsCommandsCount: u32,
    pub pRefPicMarkingOperationsCommands: *mut D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_REFERENCE_PICTURE_MARKING_OPERATION,
    pub List0RefPicModificationsCount: u32,
    pub pList0RefPicModifications: *mut D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_REFERENCE_PICTURE_LIST_MODIFICATION_OPERATION,
    pub List1RefPicModificationsCount: u32,
    pub pList1RefPicModifications: *mut D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_REFERENCE_PICTURE_LIST_MODIFICATION_OPERATION,
    pub QPMapValuesCount: u32,
    pub pRateControlQPMap: *mut i8,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264 {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264 {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_FLAG_NONE: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_FLAG_REQUEST_INTRA_CONSTRAINED_SLICES: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_FLAGS = 1u32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_REFERENCE_PICTURE_LIST_MODIFICATION_OPERATION {
    pub modification_of_pic_nums_idc: u8,
    pub abs_diff_pic_num_minus1: u32,
    pub long_term_pic_num: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_REFERENCE_PICTURE_LIST_MODIFICATION_OPERATION {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_REFERENCE_PICTURE_LIST_MODIFICATION_OPERATION {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_REFERENCE_PICTURE_MARKING_OPERATION {
    pub memory_management_control_operation: u8,
    pub difference_of_pic_nums_minus1: u32,
    pub long_term_pic_num: u32,
    pub long_term_frame_idx: u32,
    pub max_long_term_frame_idx_plus1: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_REFERENCE_PICTURE_MARKING_OPERATION {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_H264_REFERENCE_PICTURE_MARKING_OPERATION {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC {
    pub Flags: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC_FLAGS,
    pub FrameType: D3D12_VIDEO_ENCODER_FRAME_TYPE_HEVC,
    pub slice_pic_parameter_set_id: u32,
    pub PictureOrderCountNumber: u32,
    pub TemporalLayerIndex: u32,
    pub List0ReferenceFramesCount: u32,
    pub pList0ReferenceFrames: *mut u32,
    pub List1ReferenceFramesCount: u32,
    pub pList1ReferenceFrames: *mut u32,
    pub ReferenceFramesReconPictureDescriptorsCount: u32,
    pub pReferenceFramesReconPictureDescriptors: *mut D3D12_VIDEO_ENCODER_REFERENCE_PICTURE_DESCRIPTOR_HEVC,
    pub List0RefPicModificationsCount: u32,
    pub pList0RefPicModifications: *mut u32,
    pub List1RefPicModificationsCount: u32,
    pub pList1RefPicModifications: *mut u32,
    pub QPMapValuesCount: u32,
    pub pRateControlQPMap: *mut i8,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC_FLAG_NONE: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC_FLAG_REQUEST_INTRA_CONSTRAINED_SLICES: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA_HEVC_FLAGS = 1u32;
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
pub struct D3D12_VIDEO_ENCODER_PICTURE_CONTROL_DESC {
    pub IntraRefreshFrameIndex: u32,
    pub Flags: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_FLAGS,
    pub PictureControlCodecData: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_CODEC_DATA,
    pub ReferenceFrames: D3D12_VIDEO_ENCODE_REFERENCE_FRAMES,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_DESC {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_PICTURE_CONTROL_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_PICTURE_CONTROL_FLAG_NONE: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_PICTURE_CONTROL_FLAG_USED_AS_REFERENCE_PICTURE: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_FLAGS = 1u32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA {
    pub DataSize: u32,
    pub Anonymous: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_0,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_0 {
    pub pSlicesPartition_H264: *mut D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_SLICES,
    pub pSlicesPartition_HEVC: *mut D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_SLICES,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_0 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_SLICES {
    pub Anonymous: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_SLICES_0,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_SLICES {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_SLICES {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_SLICES_0 {
    pub MaxBytesPerSlice: u32,
    pub NumberOfCodingUnitsPerSlice: u32,
    pub NumberOfRowsPerSlice: u32,
    pub NumberOfSlicesPerFrame: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_SLICES_0 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA_SLICES_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC {
    pub Width: u32,
    pub Height: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_RATIO_DESC {
    pub WidthRatio: u32,
    pub HeightRatio: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_RATIO_DESC {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_RATIO_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_PROFILE_DESC {
    pub DataSize: u32,
    pub Anonymous: D3D12_VIDEO_ENCODER_PROFILE_DESC_0,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PROFILE_DESC {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PROFILE_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union D3D12_VIDEO_ENCODER_PROFILE_DESC_0 {
    pub pH264Profile: *mut D3D12_VIDEO_ENCODER_PROFILE_H264,
    pub pHEVCProfile: *mut D3D12_VIDEO_ENCODER_PROFILE_HEVC,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_PROFILE_DESC_0 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_PROFILE_DESC_0 {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_PROFILE_H264 = i32;
pub const D3D12_VIDEO_ENCODER_PROFILE_H264_MAIN: D3D12_VIDEO_ENCODER_PROFILE_H264 = 0i32;
pub const D3D12_VIDEO_ENCODER_PROFILE_H264_HIGH: D3D12_VIDEO_ENCODER_PROFILE_H264 = 1i32;
pub const D3D12_VIDEO_ENCODER_PROFILE_H264_HIGH_10: D3D12_VIDEO_ENCODER_PROFILE_H264 = 2i32;
pub type D3D12_VIDEO_ENCODER_PROFILE_HEVC = i32;
pub const D3D12_VIDEO_ENCODER_PROFILE_HEVC_MAIN: D3D12_VIDEO_ENCODER_PROFILE_HEVC = 0i32;
pub const D3D12_VIDEO_ENCODER_PROFILE_HEVC_MAIN10: D3D12_VIDEO_ENCODER_PROFILE_HEVC = 1i32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_VIDEO_ENCODER_RATE_CONTROL {
    pub Mode: D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE,
    pub Flags: D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAGS,
    pub ConfigParams: D3D12_VIDEO_ENCODER_RATE_CONTROL_CONFIGURATION_PARAMS,
    pub TargetFrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RATE_CONTROL {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RATE_CONTROL {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_RATE_CONTROL_CBR {
    pub InitialQP: u32,
    pub MinQP: u32,
    pub MaxQP: u32,
    pub MaxFrameBitSize: u64,
    pub TargetBitRate: u64,
    pub VBVCapacity: u64,
    pub InitialVBVFullness: u64,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RATE_CONTROL_CBR {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RATE_CONTROL_CBR {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_RATE_CONTROL_CONFIGURATION_PARAMS {
    pub DataSize: u32,
    pub Anonymous: D3D12_VIDEO_ENCODER_RATE_CONTROL_CONFIGURATION_PARAMS_0,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RATE_CONTROL_CONFIGURATION_PARAMS {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RATE_CONTROL_CONFIGURATION_PARAMS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union D3D12_VIDEO_ENCODER_RATE_CONTROL_CONFIGURATION_PARAMS_0 {
    pub pConfiguration_CQP: *mut D3D12_VIDEO_ENCODER_RATE_CONTROL_CQP,
    pub pConfiguration_CBR: *mut D3D12_VIDEO_ENCODER_RATE_CONTROL_CBR,
    pub pConfiguration_VBR: *mut D3D12_VIDEO_ENCODER_RATE_CONTROL_VBR,
    pub pConfiguration_QVBR: *mut D3D12_VIDEO_ENCODER_RATE_CONTROL_QVBR,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RATE_CONTROL_CONFIGURATION_PARAMS_0 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RATE_CONTROL_CONFIGURATION_PARAMS_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_RATE_CONTROL_CQP {
    pub ConstantQP_FullIntracodedFrame: u32,
    pub ConstantQP_InterPredictedFrame_PrevRefOnly: u32,
    pub ConstantQP_InterPredictedFrame_BiDirectionalRef: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RATE_CONTROL_CQP {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RATE_CONTROL_CQP {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAG_NONE: D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAG_ENABLE_DELTA_QP: D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAG_ENABLE_FRAME_ANALYSIS: D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAGS = 2u32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAG_ENABLE_QP_RANGE: D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAGS = 4u32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAG_ENABLE_INITIAL_QP: D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAGS = 8u32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAG_ENABLE_MAX_FRAME_SIZE: D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAGS = 16u32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAG_ENABLE_VBV_SIZES: D3D12_VIDEO_ENCODER_RATE_CONTROL_FLAGS = 32u32;
pub type D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE = i32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE_ABSOLUTE_QP_MAP: D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE = 0i32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE_CQP: D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE = 1i32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE_CBR: D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE = 2i32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE_VBR: D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE = 3i32;
pub const D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE_QVBR: D3D12_VIDEO_ENCODER_RATE_CONTROL_MODE = 4i32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_RATE_CONTROL_QVBR {
    pub InitialQP: u32,
    pub MinQP: u32,
    pub MaxQP: u32,
    pub MaxFrameBitSize: u64,
    pub TargetAvgBitRate: u64,
    pub PeakBitRate: u64,
    pub ConstantQualityTarget: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RATE_CONTROL_QVBR {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RATE_CONTROL_QVBR {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_RATE_CONTROL_VBR {
    pub InitialQP: u32,
    pub MinQP: u32,
    pub MaxQP: u32,
    pub MaxFrameBitSize: u64,
    pub TargetAvgBitRate: u64,
    pub PeakBitRate: u64,
    pub VBVCapacity: u64,
    pub InitialVBVFullness: u64,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RATE_CONTROL_VBR {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RATE_CONTROL_VBR {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_ENCODER_RECONSTRUCTED_PICTURE {
    pub pReconstructedPicture: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub ReconstructedPictureSubresource: u32,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RECONSTRUCTED_PICTURE {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RECONSTRUCTED_PICTURE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_VIDEO_ENCODER_REFERENCE_PICTURE_DESCRIPTOR_H264 {
    pub ReconstructedPictureResourceIndex: u32,
    pub IsLongTermReference: super::super::Foundation::BOOL,
    pub LongTermPictureIdx: u32,
    pub PictureOrderCountNumber: u32,
    pub FrameDecodingOrderNumber: u32,
    pub TemporalLayerIndex: u32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_REFERENCE_PICTURE_DESCRIPTOR_H264 {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_REFERENCE_PICTURE_DESCRIPTOR_H264 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_VIDEO_ENCODER_REFERENCE_PICTURE_DESCRIPTOR_HEVC {
    pub ReconstructedPictureResourceIndex: u32,
    pub IsRefUsedByCurrentPic: super::super::Foundation::BOOL,
    pub IsLongTermReference: super::super::Foundation::BOOL,
    pub PictureOrderCountNumber: u32,
    pub TemporalLayerIndex: u32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_REFERENCE_PICTURE_DESCRIPTOR_HEVC {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_REFERENCE_PICTURE_DESCRIPTOR_HEVC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_VIDEO_ENCODER_RESOLVE_METADATA_INPUT_ARGUMENTS {
    pub EncoderCodec: D3D12_VIDEO_ENCODER_CODEC,
    pub EncoderProfile: D3D12_VIDEO_ENCODER_PROFILE_DESC,
    pub EncoderInputFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub EncodedPictureEffectiveResolution: D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC,
    pub HWLayoutMetadata: D3D12_VIDEO_ENCODER_ENCODE_OPERATION_METADATA_BUFFER,
}
#[cfg(all(feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RESOLVE_METADATA_INPUT_ARGUMENTS {}
#[cfg(all(feature = "Win32_Graphics_Direct3D12", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RESOLVE_METADATA_INPUT_ARGUMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_ENCODER_RESOLVE_METADATA_OUTPUT_ARGUMENTS {
    pub ResolvedLayoutMetadata: D3D12_VIDEO_ENCODER_ENCODE_OPERATION_METADATA_BUFFER,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_RESOLVE_METADATA_OUTPUT_ARGUMENTS {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_RESOLVE_METADATA_OUTPUT_ARGUMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_DESC {
    pub Flags: D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAGS,
    pub IntraRefreshConfig: D3D12_VIDEO_ENCODER_INTRA_REFRESH,
    pub RateControl: D3D12_VIDEO_ENCODER_RATE_CONTROL,
    pub PictureTargetResolution: D3D12_VIDEO_ENCODER_PICTURE_RESOLUTION_DESC,
    pub SelectedLayoutMode: D3D12_VIDEO_ENCODER_FRAME_SUBREGION_LAYOUT_MODE,
    pub FrameSubregionsLayoutData: D3D12_VIDEO_ENCODER_PICTURE_CONTROL_SUBREGIONS_LAYOUT_DATA,
    pub CodecGopSequence: D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_DESC {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAG_NONE: D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAG_RESOLUTION_CHANGE: D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAG_RATE_CONTROL_CHANGE: D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAGS = 2u32;
pub const D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAG_SUBREGION_LAYOUT_CHANGE: D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAGS = 4u32;
pub const D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAG_REQUEST_INTRA_REFRESH: D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAGS = 8u32;
pub const D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAG_GOP_SEQUENCE_CHANGE: D3D12_VIDEO_ENCODER_SEQUENCE_CONTROL_FLAGS = 16u32;
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE {
    pub DataSize: u32,
    pub Anonymous: D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_0,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_0 {
    pub pH264GroupOfPictures: *mut D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_H264,
    pub pHEVCGroupOfPictures: *mut D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_HEVC,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_0 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_H264 {
    pub GOPLength: u32,
    pub PPicturePeriod: u32,
    pub pic_order_cnt_type: u8,
    pub log2_max_frame_num_minus4: u8,
    pub log2_max_pic_order_cnt_lsb_minus4: u8,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_H264 {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_H264 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_HEVC {
    pub GOPLength: u32,
    pub PPicturePeriod: u32,
    pub log2_max_pic_order_cnt_lsb_minus4: u8,
}
impl ::core::marker::Copy for D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_HEVC {}
impl ::core::clone::Clone for D3D12_VIDEO_ENCODER_SEQUENCE_GOP_STRUCTURE_HEVC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_NONE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_GENERAL_SUPPORT_OK: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_RATE_CONTROL_RECONFIGURATION_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 2u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_RESOLUTION_RECONFIGURATION_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 4u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_RATE_CONTROL_VBV_SIZE_CONFIG_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 8u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_RATE_CONTROL_FRAME_ANALYSIS_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 16u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_RECONSTRUCTED_FRAMES_REQUIRE_TEXTURE_ARRAYS: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 32u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_RATE_CONTROL_DELTA_QP_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 64u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_SUBREGION_LAYOUT_RECONFIGURATION_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 128u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_RATE_CONTROL_ADJUSTABLE_QP_RANGE_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 256u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_RATE_CONTROL_INITIAL_QP_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 512u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_RATE_CONTROL_MAX_FRAME_SIZE_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 1024u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_SEQUENCE_GOP_RECONFIGURATION_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 2048u32;
pub const D3D12_VIDEO_ENCODER_SUPPORT_FLAG_MOTION_ESTIMATION_PRECISION_MODE_LIMIT_AVAILABLE: D3D12_VIDEO_ENCODER_SUPPORT_FLAGS = 4096u32;
pub type D3D12_VIDEO_ENCODER_TIER_HEVC = i32;
pub const D3D12_VIDEO_ENCODER_TIER_HEVC_MAIN: D3D12_VIDEO_ENCODER_TIER_HEVC = 0i32;
pub const D3D12_VIDEO_ENCODER_TIER_HEVC_HIGH: D3D12_VIDEO_ENCODER_TIER_HEVC = 1i32;
pub type D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_NONE: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 0u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_CODEC_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 1u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_INPUT_FORMAT_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 8u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_CODEC_CONFIGURATION_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 16u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_RATE_CONTROL_MODE_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 32u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_RATE_CONTROL_CONFIGURATION_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 64u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_INTRA_REFRESH_MODE_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 128u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_SUBREGION_LAYOUT_MODE_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 256u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_RESOLUTION_NOT_SUPPORTED_IN_LIST: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 512u32;
pub const D3D12_VIDEO_ENCODER_VALIDATION_FLAG_GOP_STRUCTURE_NOT_SUPPORTED: D3D12_VIDEO_ENCODER_VALIDATION_FLAGS = 2048u32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_ENCODE_REFERENCE_FRAMES {
    pub NumTexture2Ds: u32,
    pub ppTexture2Ds: *mut super::super::Graphics::Direct3D12::ID3D12Resource,
    pub pSubresources: *mut u32,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_ENCODE_REFERENCE_FRAMES {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_ENCODE_REFERENCE_FRAMES {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_EXTENSION_COMMAND_DESC {
    pub NodeMask: u32,
    pub CommandId: ::windows_sys::core::GUID,
}
impl ::core::marker::Copy for D3D12_VIDEO_EXTENSION_COMMAND_DESC {}
impl ::core::clone::Clone for D3D12_VIDEO_EXTENSION_COMMAND_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
pub struct D3D12_VIDEO_EXTENSION_COMMAND_INFO {
    pub CommandId: ::windows_sys::core::GUID,
    pub Name: super::super::Foundation::PWSTR,
    pub CommandListSupportFlags: super::super::Graphics::Direct3D12::D3D12_COMMAND_LIST_SUPPORT_FLAGS,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::marker::Copy for D3D12_VIDEO_EXTENSION_COMMAND_INFO {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::clone::Clone for D3D12_VIDEO_EXTENSION_COMMAND_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_FLAGS = u32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_FLAG_NONE: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_FLAGS = 0u32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_FLAG_READ: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_FLAGS = 1u32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_FLAG_WRITE: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_FLAGS = 2u32;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_INFO {
    pub Name: super::super::Foundation::PWSTR,
    pub Type: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE,
    pub Flags: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_FLAGS,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_INFO {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE = i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE_CREATION: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE = 0i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE_INITIALIZATION: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE = 1i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE_EXECUTION: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE = 2i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE_CAPS_INPUT: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE = 3i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE_CAPS_OUTPUT: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE = 4i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE_DEVICE_EXECUTE_INPUT: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE = 5i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE_DEVICE_EXECUTE_OUTPUT: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_STAGE = 6i32;
pub type D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_UINT8: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 0i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_UINT16: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 1i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_UINT32: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 2i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_UINT64: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 3i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_SINT8: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 4i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_SINT16: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 5i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_SINT32: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 6i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_SINT64: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 7i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_FLOAT: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 8i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_DOUBLE: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 9i32;
pub const D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE_RESOURCE: D3D12_VIDEO_EXTENSION_COMMAND_PARAMETER_TYPE = 10i32;
pub type D3D12_VIDEO_FIELD_TYPE = i32;
pub const D3D12_VIDEO_FIELD_TYPE_NONE: D3D12_VIDEO_FIELD_TYPE = 0i32;
pub const D3D12_VIDEO_FIELD_TYPE_INTERLACED_TOP_FIELD_FIRST: D3D12_VIDEO_FIELD_TYPE = 1i32;
pub const D3D12_VIDEO_FIELD_TYPE_INTERLACED_BOTTOM_FIELD_FIRST: D3D12_VIDEO_FIELD_TYPE = 2i32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_VIDEO_FORMAT {
    pub Format: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub ColorSpace: super::super::Graphics::Dxgi::Common::DXGI_COLOR_SPACE_TYPE,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_VIDEO_FORMAT {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_VIDEO_FORMAT {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE = i32;
pub const D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE_NONE: D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE = 0i32;
pub const D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE_FIELD_BASED: D3D12_VIDEO_FRAME_CODED_INTERLACE_TYPE = 1i32;
pub type D3D12_VIDEO_FRAME_STEREO_FORMAT = i32;
pub const D3D12_VIDEO_FRAME_STEREO_FORMAT_NONE: D3D12_VIDEO_FRAME_STEREO_FORMAT = 0i32;
pub const D3D12_VIDEO_FRAME_STEREO_FORMAT_MONO: D3D12_VIDEO_FRAME_STEREO_FORMAT = 1i32;
pub const D3D12_VIDEO_FRAME_STEREO_FORMAT_HORIZONTAL: D3D12_VIDEO_FRAME_STEREO_FORMAT = 2i32;
pub const D3D12_VIDEO_FRAME_STEREO_FORMAT_VERTICAL: D3D12_VIDEO_FRAME_STEREO_FORMAT = 3i32;
pub const D3D12_VIDEO_FRAME_STEREO_FORMAT_SEPARATE: D3D12_VIDEO_FRAME_STEREO_FORMAT = 4i32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_VIDEO_MOTION_ESTIMATOR_DESC {
    pub NodeMask: u32,
    pub InputFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub BlockSize: D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE,
    pub Precision: D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION,
    pub SizeRange: D3D12_VIDEO_SIZE_RANGE,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_VIDEO_MOTION_ESTIMATOR_DESC {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_VIDEO_MOTION_ESTIMATOR_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_MOTION_ESTIMATOR_INPUT {
    pub pInputTexture2D: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub InputSubresourceIndex: u32,
    pub pReferenceTexture2D: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub ReferenceSubresourceIndex: u32,
    pub pHintMotionVectorHeap: ID3D12VideoMotionVectorHeap,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_MOTION_ESTIMATOR_INPUT {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_MOTION_ESTIMATOR_INPUT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_MOTION_ESTIMATOR_OUTPUT {
    pub pMotionVectorHeap: ID3D12VideoMotionVectorHeap,
}
impl ::core::marker::Copy for D3D12_VIDEO_MOTION_ESTIMATOR_OUTPUT {}
impl ::core::clone::Clone for D3D12_VIDEO_MOTION_ESTIMATOR_OUTPUT {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE = i32;
pub const D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_8X8: D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE = 0i32;
pub const D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_16X16: D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE = 1i32;
pub type D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_FLAGS = u32;
pub const D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_FLAG_NONE: D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_FLAGS = 0u32;
pub const D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_FLAG_8X8: D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_FLAGS = 1u32;
pub const D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_FLAG_16X16: D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE_FLAGS = 2u32;
pub type D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION = i32;
pub const D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION_QUARTER_PEL: D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION = 0i32;
pub type D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION_FLAGS = u32;
pub const D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION_FLAG_NONE: D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION_FLAGS = 0u32;
pub const D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION_FLAG_QUARTER_PEL: D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION_FLAGS = 1u32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_VIDEO_MOTION_VECTOR_HEAP_DESC {
    pub NodeMask: u32,
    pub InputFormat: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub BlockSize: D3D12_VIDEO_MOTION_ESTIMATOR_SEARCH_BLOCK_SIZE,
    pub Precision: D3D12_VIDEO_MOTION_ESTIMATOR_VECTOR_PRECISION,
    pub SizeRange: D3D12_VIDEO_SIZE_RANGE,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_VIDEO_MOTION_VECTOR_HEAP_DESC {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_VIDEO_MOTION_VECTOR_HEAP_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_VIDEO_PROCESS_ALPHA_BLENDING {
    pub Enable: super::super::Foundation::BOOL,
    pub Alpha: f32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_ALPHA_BLENDING {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_ALPHA_BLENDING {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE = i32;
pub const D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_OPAQUE: D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE = 0i32;
pub const D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_BACKGROUND: D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE = 1i32;
pub const D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_DESTINATION: D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE = 2i32;
pub const D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE_SOURCE_STREAM: D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE = 3i32;
pub type D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_NONE: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 0u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_DENOISE: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 1u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_DERINGING: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 2u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_EDGE_ENHANCEMENT: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 4u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_COLOR_CORRECTION: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 8u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_FLESH_TONE_MAPPING: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 16u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_IMAGE_STABILIZATION: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 32u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_SUPER_RESOLUTION: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 64u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_ANAMORPHIC_SCALING: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 128u32;
pub const D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAG_CUSTOM: D3D12_VIDEO_PROCESS_AUTO_PROCESSING_FLAGS = 2147483648u32;
pub type D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS = u32;
pub const D3D12_VIDEO_PROCESS_DEINTERLACE_FLAG_NONE: D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS = 0u32;
pub const D3D12_VIDEO_PROCESS_DEINTERLACE_FLAG_BOB: D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS = 1u32;
pub const D3D12_VIDEO_PROCESS_DEINTERLACE_FLAG_CUSTOM: D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS = 2147483648u32;
pub type D3D12_VIDEO_PROCESS_FEATURE_FLAGS = u32;
pub const D3D12_VIDEO_PROCESS_FEATURE_FLAG_NONE: D3D12_VIDEO_PROCESS_FEATURE_FLAGS = 0u32;
pub const D3D12_VIDEO_PROCESS_FEATURE_FLAG_ALPHA_FILL: D3D12_VIDEO_PROCESS_FEATURE_FLAGS = 1u32;
pub const D3D12_VIDEO_PROCESS_FEATURE_FLAG_LUMA_KEY: D3D12_VIDEO_PROCESS_FEATURE_FLAGS = 2u32;
pub const D3D12_VIDEO_PROCESS_FEATURE_FLAG_STEREO: D3D12_VIDEO_PROCESS_FEATURE_FLAGS = 4u32;
pub const D3D12_VIDEO_PROCESS_FEATURE_FLAG_ROTATION: D3D12_VIDEO_PROCESS_FEATURE_FLAGS = 8u32;
pub const D3D12_VIDEO_PROCESS_FEATURE_FLAG_FLIP: D3D12_VIDEO_PROCESS_FEATURE_FLAGS = 16u32;
pub const D3D12_VIDEO_PROCESS_FEATURE_FLAG_ALPHA_BLENDING: D3D12_VIDEO_PROCESS_FEATURE_FLAGS = 32u32;
pub const D3D12_VIDEO_PROCESS_FEATURE_FLAG_PIXEL_ASPECT_RATIO: D3D12_VIDEO_PROCESS_FEATURE_FLAGS = 64u32;
pub type D3D12_VIDEO_PROCESS_FILTER = i32;
pub const D3D12_VIDEO_PROCESS_FILTER_BRIGHTNESS: D3D12_VIDEO_PROCESS_FILTER = 0i32;
pub const D3D12_VIDEO_PROCESS_FILTER_CONTRAST: D3D12_VIDEO_PROCESS_FILTER = 1i32;
pub const D3D12_VIDEO_PROCESS_FILTER_HUE: D3D12_VIDEO_PROCESS_FILTER = 2i32;
pub const D3D12_VIDEO_PROCESS_FILTER_SATURATION: D3D12_VIDEO_PROCESS_FILTER = 3i32;
pub const D3D12_VIDEO_PROCESS_FILTER_NOISE_REDUCTION: D3D12_VIDEO_PROCESS_FILTER = 4i32;
pub const D3D12_VIDEO_PROCESS_FILTER_EDGE_ENHANCEMENT: D3D12_VIDEO_PROCESS_FILTER = 5i32;
pub const D3D12_VIDEO_PROCESS_FILTER_ANAMORPHIC_SCALING: D3D12_VIDEO_PROCESS_FILTER = 6i32;
pub const D3D12_VIDEO_PROCESS_FILTER_STEREO_ADJUSTMENT: D3D12_VIDEO_PROCESS_FILTER = 7i32;
pub type D3D12_VIDEO_PROCESS_FILTER_FLAGS = u32;
pub const D3D12_VIDEO_PROCESS_FILTER_FLAG_NONE: D3D12_VIDEO_PROCESS_FILTER_FLAGS = 0u32;
pub const D3D12_VIDEO_PROCESS_FILTER_FLAG_BRIGHTNESS: D3D12_VIDEO_PROCESS_FILTER_FLAGS = 1u32;
pub const D3D12_VIDEO_PROCESS_FILTER_FLAG_CONTRAST: D3D12_VIDEO_PROCESS_FILTER_FLAGS = 2u32;
pub const D3D12_VIDEO_PROCESS_FILTER_FLAG_HUE: D3D12_VIDEO_PROCESS_FILTER_FLAGS = 4u32;
pub const D3D12_VIDEO_PROCESS_FILTER_FLAG_SATURATION: D3D12_VIDEO_PROCESS_FILTER_FLAGS = 8u32;
pub const D3D12_VIDEO_PROCESS_FILTER_FLAG_NOISE_REDUCTION: D3D12_VIDEO_PROCESS_FILTER_FLAGS = 16u32;
pub const D3D12_VIDEO_PROCESS_FILTER_FLAG_EDGE_ENHANCEMENT: D3D12_VIDEO_PROCESS_FILTER_FLAGS = 32u32;
pub const D3D12_VIDEO_PROCESS_FILTER_FLAG_ANAMORPHIC_SCALING: D3D12_VIDEO_PROCESS_FILTER_FLAGS = 64u32;
pub const D3D12_VIDEO_PROCESS_FILTER_FLAG_STEREO_ADJUSTMENT: D3D12_VIDEO_PROCESS_FILTER_FLAGS = 128u32;
#[repr(C)]
pub struct D3D12_VIDEO_PROCESS_FILTER_RANGE {
    pub Minimum: i32,
    pub Maximum: i32,
    pub Default: i32,
    pub Multiplier: f32,
}
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_FILTER_RANGE {}
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_FILTER_RANGE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_PROCESS_INPUT_STREAM {
    pub pTexture2D: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub Subresource: u32,
    pub ReferenceSet: D3D12_VIDEO_PROCESS_REFERENCE_SET,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_INPUT_STREAM {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_INPUT_STREAM {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
pub struct D3D12_VIDEO_PROCESS_INPUT_STREAM_ARGUMENTS {
    pub InputStream: [D3D12_VIDEO_PROCESS_INPUT_STREAM; 2],
    pub Transform: D3D12_VIDEO_PROCESS_TRANSFORM,
    pub Flags: D3D12_VIDEO_PROCESS_INPUT_STREAM_FLAGS,
    pub RateInfo: D3D12_VIDEO_PROCESS_INPUT_STREAM_RATE,
    pub FilterLevels: [i32; 32],
    pub AlphaBlending: D3D12_VIDEO_PROCESS_ALPHA_BLENDING,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_INPUT_STREAM_ARGUMENTS {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_INPUT_STREAM_ARGUMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
pub struct D3D12_VIDEO_PROCESS_INPUT_STREAM_ARGUMENTS1 {
    pub InputStream: [D3D12_VIDEO_PROCESS_INPUT_STREAM; 2],
    pub Transform: D3D12_VIDEO_PROCESS_TRANSFORM,
    pub Flags: D3D12_VIDEO_PROCESS_INPUT_STREAM_FLAGS,
    pub RateInfo: D3D12_VIDEO_PROCESS_INPUT_STREAM_RATE,
    pub FilterLevels: [i32; 32],
    pub AlphaBlending: D3D12_VIDEO_PROCESS_ALPHA_BLENDING,
    pub FieldType: D3D12_VIDEO_FIELD_TYPE,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_INPUT_STREAM_ARGUMENTS1 {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_INPUT_STREAM_ARGUMENTS1 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC {
    pub Format: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub ColorSpace: super::super::Graphics::Dxgi::Common::DXGI_COLOR_SPACE_TYPE,
    pub SourceAspectRatio: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub DestinationAspectRatio: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub FrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub SourceSizeRange: D3D12_VIDEO_SIZE_RANGE,
    pub DestinationSizeRange: D3D12_VIDEO_SIZE_RANGE,
    pub EnableOrientation: super::super::Foundation::BOOL,
    pub FilterFlags: D3D12_VIDEO_PROCESS_FILTER_FLAGS,
    pub StereoFormat: D3D12_VIDEO_FRAME_STEREO_FORMAT,
    pub FieldType: D3D12_VIDEO_FIELD_TYPE,
    pub DeinterlaceMode: D3D12_VIDEO_PROCESS_DEINTERLACE_FLAGS,
    pub EnableAlphaBlending: super::super::Foundation::BOOL,
    pub LumaKey: D3D12_VIDEO_PROCESS_LUMA_KEY,
    pub NumPastFrames: u32,
    pub NumFutureFrames: u32,
    pub EnableAutoProcessing: super::super::Foundation::BOOL,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_INPUT_STREAM_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_PROCESS_INPUT_STREAM_FLAGS = u32;
pub const D3D12_VIDEO_PROCESS_INPUT_STREAM_FLAG_NONE: D3D12_VIDEO_PROCESS_INPUT_STREAM_FLAGS = 0u32;
pub const D3D12_VIDEO_PROCESS_INPUT_STREAM_FLAG_FRAME_DISCONTINUITY: D3D12_VIDEO_PROCESS_INPUT_STREAM_FLAGS = 1u32;
pub const D3D12_VIDEO_PROCESS_INPUT_STREAM_FLAG_FRAME_REPEAT: D3D12_VIDEO_PROCESS_INPUT_STREAM_FLAGS = 2u32;
#[repr(C)]
pub struct D3D12_VIDEO_PROCESS_INPUT_STREAM_RATE {
    pub OutputIndex: u32,
    pub InputFrameOrField: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_INPUT_STREAM_RATE {}
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_INPUT_STREAM_RATE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_VIDEO_PROCESS_LUMA_KEY {
    pub Enable: super::super::Foundation::BOOL,
    pub Lower: f32,
    pub Upper: f32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_LUMA_KEY {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_LUMA_KEY {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_PROCESS_ORIENTATION = i32;
pub const D3D12_VIDEO_PROCESS_ORIENTATION_DEFAULT: D3D12_VIDEO_PROCESS_ORIENTATION = 0i32;
pub const D3D12_VIDEO_PROCESS_ORIENTATION_FLIP_HORIZONTAL: D3D12_VIDEO_PROCESS_ORIENTATION = 1i32;
pub const D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_90: D3D12_VIDEO_PROCESS_ORIENTATION = 2i32;
pub const D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_90_FLIP_HORIZONTAL: D3D12_VIDEO_PROCESS_ORIENTATION = 3i32;
pub const D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_180: D3D12_VIDEO_PROCESS_ORIENTATION = 4i32;
pub const D3D12_VIDEO_PROCESS_ORIENTATION_FLIP_VERTICAL: D3D12_VIDEO_PROCESS_ORIENTATION = 5i32;
pub const D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_270: D3D12_VIDEO_PROCESS_ORIENTATION = 6i32;
pub const D3D12_VIDEO_PROCESS_ORIENTATION_CLOCKWISE_270_FLIP_HORIZONTAL: D3D12_VIDEO_PROCESS_ORIENTATION = 7i32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_PROCESS_OUTPUT_STREAM {
    pub pTexture2D: super::super::Graphics::Direct3D12::ID3D12Resource,
    pub Subresource: u32,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_OUTPUT_STREAM {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_OUTPUT_STREAM {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
pub struct D3D12_VIDEO_PROCESS_OUTPUT_STREAM_ARGUMENTS {
    pub OutputStream: [D3D12_VIDEO_PROCESS_OUTPUT_STREAM; 2],
    pub TargetRectangle: super::super::Foundation::RECT,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_OUTPUT_STREAM_ARGUMENTS {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D12"))]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_OUTPUT_STREAM_ARGUMENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
pub struct D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC {
    pub Format: super::super::Graphics::Dxgi::Common::DXGI_FORMAT,
    pub ColorSpace: super::super::Graphics::Dxgi::Common::DXGI_COLOR_SPACE_TYPE,
    pub AlphaFillMode: D3D12_VIDEO_PROCESS_ALPHA_FILL_MODE,
    pub AlphaFillModeSourceStreamIndex: u32,
    pub BackgroundColor: [f32; 4],
    pub FrameRate: super::super::Graphics::Dxgi::Common::DXGI_RATIONAL,
    pub EnableStereo: super::super::Foundation::BOOL,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Dxgi_Common"))]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_OUTPUT_STREAM_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D12")]
pub struct D3D12_VIDEO_PROCESS_REFERENCE_SET {
    pub NumPastFrames: u32,
    pub ppPastFrames: *mut super::super::Graphics::Direct3D12::ID3D12Resource,
    pub pPastSubresources: *mut u32,
    pub NumFutureFrames: u32,
    pub ppFutureFrames: *mut super::super::Graphics::Direct3D12::ID3D12Resource,
    pub pFutureSubresources: *mut u32,
}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_REFERENCE_SET {}
#[cfg(feature = "Win32_Graphics_Direct3D12")]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_REFERENCE_SET {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_PROCESS_SUPPORT_FLAGS = u32;
pub const D3D12_VIDEO_PROCESS_SUPPORT_FLAG_NONE: D3D12_VIDEO_PROCESS_SUPPORT_FLAGS = 0u32;
pub const D3D12_VIDEO_PROCESS_SUPPORT_FLAG_SUPPORTED: D3D12_VIDEO_PROCESS_SUPPORT_FLAGS = 1u32;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct D3D12_VIDEO_PROCESS_TRANSFORM {
    pub SourceRectangle: super::super::Foundation::RECT,
    pub DestinationRectangle: super::super::Foundation::RECT,
    pub Orientation: D3D12_VIDEO_PROCESS_ORIENTATION,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for D3D12_VIDEO_PROCESS_TRANSFORM {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for D3D12_VIDEO_PROCESS_TRANSFORM {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_PROTECTED_RESOURCE_SUPPORT_FLAGS = u32;
pub const D3D12_VIDEO_PROTECTED_RESOURCE_SUPPORT_FLAG_NONE: D3D12_VIDEO_PROTECTED_RESOURCE_SUPPORT_FLAGS = 0u32;
pub const D3D12_VIDEO_PROTECTED_RESOURCE_SUPPORT_FLAG_SUPPORTED: D3D12_VIDEO_PROTECTED_RESOURCE_SUPPORT_FLAGS = 1u32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
pub struct D3D12_VIDEO_SAMPLE {
    pub Width: u32,
    pub Height: u32,
    pub Format: D3D12_VIDEO_FORMAT,
}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::marker::Copy for D3D12_VIDEO_SAMPLE {}
#[cfg(feature = "Win32_Graphics_Dxgi_Common")]
impl ::core::clone::Clone for D3D12_VIDEO_SAMPLE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3D12_VIDEO_SCALE_SUPPORT {
    pub OutputSizeRange: D3D12_VIDEO_SIZE_RANGE,
    pub Flags: D3D12_VIDEO_SCALE_SUPPORT_FLAGS,
}
impl ::core::marker::Copy for D3D12_VIDEO_SCALE_SUPPORT {}
impl ::core::clone::Clone for D3D12_VIDEO_SCALE_SUPPORT {
    fn clone(&self) -> Self {
        *self
    }
}
pub type D3D12_VIDEO_SCALE_SUPPORT_FLAGS = u32;
pub const D3D12_VIDEO_SCALE_SUPPORT_FLAG_NONE: D3D12_VIDEO_SCALE_SUPPORT_FLAGS = 0u32;
pub const D3D12_VIDEO_SCALE_SUPPORT_FLAG_POW2_ONLY: D3D12_VIDEO_SCALE_SUPPORT_FLAGS = 1u32;
pub const D3D12_VIDEO_SCALE_SUPPORT_FLAG_EVEN_DIMENSIONS_ONLY: D3D12_VIDEO_SCALE_SUPPORT_FLAGS = 2u32;
#[repr(C)]
pub struct D3D12_VIDEO_SIZE_RANGE {
    pub MaxWidth: u32,
    pub MaxHeight: u32,
    pub MinWidth: u32,
    pub MinHeight: u32,
}
impl ::core::marker::Copy for D3D12_VIDEO_SIZE_RANGE {}
impl ::core::clone::Clone for D3D12_VIDEO_SIZE_RANGE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
pub struct D3DCONTENTPROTECTIONCAPS {
    pub Caps: u32,
    pub KeyExchangeType: ::windows_sys::core::GUID,
    pub BufferAlignmentStart: u32,
    pub BlockAlignmentSize: u32,
    pub ProtectedMemorySize: u64,
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
impl ::core::marker::Copy for D3DCONTENTPROTECTIONCAPS {}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
impl ::core::clone::Clone for D3DCONTENTPROTECTIONCAPS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C, packed(4))]
#[cfg(any(target_arch = "x86",))]
pub struct D3DCONTENTPROTECTIONCAPS {
    pub Caps: u32,
    pub KeyExchangeType: ::windows_sys::core::GUID,
    pub BufferAlignmentStart: u32,
    pub BlockAlignmentSize: u32,
    pub ProtectedMemorySize: u64,
}
#[cfg(any(target_arch = "x86",))]
impl ::core::marker::Copy for D3DCONTENTPROTECTIONCAPS {}
#[cfg(any(target_arch = "x86",))]
impl ::core::clone::Clone for D3DCONTENTPROTECTIONCAPS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct D3DOVERLAYCAPS {
    pub Caps: u32,
    pub MaxOverlayDisplayWidth: u32,
    pub MaxOverlayDisplayHeight: u32,
}
impl ::core::marker::Copy for D3DOVERLAYCAPS {}
impl ::core::clone::Clone for D3DOVERLAYCAPS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DEVICE_INFO {
    pub pFriendlyDeviceName: super::super::Foundation::BSTR,
    pub pUniqueDeviceName: super::super::Foundation::BSTR,
    pub pManufacturerName: super::super::Foundation::BSTR,
    pub pModelName: super::super::Foundation::BSTR,
    pub pIconURL: super::super::Foundation::BSTR,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DEVICE_INFO {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DEVICE_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub const DEVPKEY_DeviceInterface_IsVirtualCamera: super::super::UI::Shell::PropertiesSystem::PROPERTYKEY = super::super::UI::Shell::PropertiesSystem::PROPERTYKEY {
    fmtid: ::windows_sys::core::GUID { data1: 1859937037, data2: 49891, data3: 17335, data4: [178, 209, 32, 82, 90, 26, 241, 32] },
    pid: 3u32,
};
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DIRTYRECT_INFO {
    pub FrameNumber: u32,
    pub NumDirtyRects: u32,
    pub DirtyRects: [super::super::Foundation::RECT; 1],
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DIRTYRECT_INFO {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DIRTYRECT_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA2_AES_CTR_IV {
    pub IV: u64,
    pub Count: u64,
}
impl ::core::marker::Copy for DXVA2_AES_CTR_IV {}
impl ::core::clone::Clone for DXVA2_AES_CTR_IV {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA2_AYUVSample16 {
    pub Cr: u16,
    pub Cb: u16,
    pub Y: u16,
    pub Alpha: u16,
}
impl ::core::marker::Copy for DXVA2_AYUVSample16 {}
impl ::core::clone::Clone for DXVA2_AYUVSample16 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA2_AYUVSample8 {
    pub Cr: u8,
    pub Cb: u8,
    pub Y: u8,
    pub Alpha: u8,
}
impl ::core::marker::Copy for DXVA2_AYUVSample8 {}
impl ::core::clone::Clone for DXVA2_AYUVSample8 {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA2_BufferfType = i32;
pub const DXVA2_PictureParametersBufferType: DXVA2_BufferfType = 0i32;
pub const DXVA2_MacroBlockControlBufferType: DXVA2_BufferfType = 1i32;
pub const DXVA2_ResidualDifferenceBufferType: DXVA2_BufferfType = 2i32;
pub const DXVA2_DeblockingControlBufferType: DXVA2_BufferfType = 3i32;
pub const DXVA2_InverseQuantizationMatrixBufferType: DXVA2_BufferfType = 4i32;
pub const DXVA2_SliceControlBufferType: DXVA2_BufferfType = 5i32;
pub const DXVA2_BitStreamDateBufferType: DXVA2_BufferfType = 6i32;
pub const DXVA2_MotionVectorBuffer: DXVA2_BufferfType = 7i32;
pub const DXVA2_FilmGrainBuffer: DXVA2_BufferfType = 8i32;
#[repr(C)]
pub struct DXVA2_ConfigPictureDecode {
    pub guidConfigBitstreamEncryption: ::windows_sys::core::GUID,
    pub guidConfigMBcontrolEncryption: ::windows_sys::core::GUID,
    pub guidConfigResidDiffEncryption: ::windows_sys::core::GUID,
    pub ConfigBitstreamRaw: u32,
    pub ConfigMBcontrolRasterOrder: u32,
    pub ConfigResidDiffHost: u32,
    pub ConfigSpatialResid8: u32,
    pub ConfigResid8Subtraction: u32,
    pub ConfigSpatialHost8or9Clipping: u32,
    pub ConfigSpatialResidInterleaved: u32,
    pub ConfigIntraResidUnsigned: u32,
    pub ConfigResidDiffAccelerator: u32,
    pub ConfigHostInverseScan: u32,
    pub ConfigSpecificIDCT: u32,
    pub Config4GroupedCoefs: u32,
    pub ConfigMinRenderTargetBuffCount: u16,
    pub ConfigDecoderSpecific: u16,
}
impl ::core::marker::Copy for DXVA2_ConfigPictureDecode {}
impl ::core::clone::Clone for DXVA2_ConfigPictureDecode {
    fn clone(&self) -> Self {
        *self
    }
}
pub const DXVA2_DECODE_GET_DRIVER_HANDLE: u32 = 1829u32;
pub const DXVA2_DECODE_SPECIFY_ENCRYPTED_BLOCKS: u32 = 1828u32;
#[repr(C)]
pub struct DXVA2_DecodeBufferDesc {
    pub CompressedBufferType: DXVA2_BufferfType,
    pub BufferIndex: u32,
    pub DataOffset: u32,
    pub DataSize: u32,
    pub FirstMBaddress: u32,
    pub NumMBsInBuffer: u32,
    pub Width: u32,
    pub Height: u32,
    pub Stride: u32,
    pub ReservedBits: u32,
    pub pvPVPState: *mut ::core::ffi::c_void,
}
impl ::core::marker::Copy for DXVA2_DecodeBufferDesc {}
impl ::core::clone::Clone for DXVA2_DecodeBufferDesc {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA2_DecodeExecuteParams {
    pub NumCompBuffers: u32,
    pub pCompressedBuffers: *mut DXVA2_DecodeBufferDesc,
    pub pExtensionData: *mut DXVA2_DecodeExtensionData,
}
impl ::core::marker::Copy for DXVA2_DecodeExecuteParams {}
impl ::core::clone::Clone for DXVA2_DecodeExecuteParams {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA2_DecodeExtensionData {
    pub Function: u32,
    pub pPrivateInputData: *mut ::core::ffi::c_void,
    pub PrivateInputDataSize: u32,
    pub pPrivateOutputData: *mut ::core::ffi::c_void,
    pub PrivateOutputDataSize: u32,
}
impl ::core::marker::Copy for DXVA2_DecodeExtensionData {}
impl ::core::clone::Clone for DXVA2_DecodeExtensionData {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA2_DeinterlaceTech = i32;
pub const DXVA2_DeinterlaceTech_Unknown: DXVA2_DeinterlaceTech = 0i32;
pub const DXVA2_DeinterlaceTech_BOBLineReplicate: DXVA2_DeinterlaceTech = 1i32;
pub const DXVA2_DeinterlaceTech_BOBVerticalStretch: DXVA2_DeinterlaceTech = 2i32;
pub const DXVA2_DeinterlaceTech_BOBVerticalStretch4Tap: DXVA2_DeinterlaceTech = 4i32;
pub const DXVA2_DeinterlaceTech_MedianFiltering: DXVA2_DeinterlaceTech = 8i32;
pub const DXVA2_DeinterlaceTech_EdgeFiltering: DXVA2_DeinterlaceTech = 16i32;
pub const DXVA2_DeinterlaceTech_FieldAdaptive: DXVA2_DeinterlaceTech = 32i32;
pub const DXVA2_DeinterlaceTech_PixelAdaptive: DXVA2_DeinterlaceTech = 64i32;
pub const DXVA2_DeinterlaceTech_MotionVectorSteered: DXVA2_DeinterlaceTech = 128i32;
pub const DXVA2_DeinterlaceTech_InverseTelecine: DXVA2_DeinterlaceTech = 256i32;
pub const DXVA2_DeinterlaceTech_Mask: DXVA2_DeinterlaceTech = 511i32;
pub type DXVA2_DestData = i32;
pub const DXVA2_DestData_RFF: DXVA2_DestData = 1i32;
pub const DXVA2_DestData_TFF: DXVA2_DestData = 2i32;
pub const DXVA2_DestData_RFF_TFF_Present: DXVA2_DestData = 4i32;
pub const DXVA2_DestData_Mask: DXVA2_DestData = 65535i32;
pub type DXVA2_DetailFilterTech = i32;
pub const DXVA2_DetailFilterTech_Unsupported: DXVA2_DetailFilterTech = 0i32;
pub const DXVA2_DetailFilterTech_Unknown: DXVA2_DetailFilterTech = 1i32;
pub const DXVA2_DetailFilterTech_Edge: DXVA2_DetailFilterTech = 2i32;
pub const DXVA2_DetailFilterTech_Sharpening: DXVA2_DetailFilterTech = 4i32;
pub const DXVA2_DetailFilterTech_Mask: DXVA2_DetailFilterTech = 7i32;
pub const DXVA2_E_NEW_VIDEO_DEVICE: ::windows_sys::core::HRESULT = -2147217407i32;
pub const DXVA2_E_NOT_AVAILABLE: ::windows_sys::core::HRESULT = -2147217405i32;
pub const DXVA2_E_NOT_INITIALIZED: ::windows_sys::core::HRESULT = -2147217408i32;
pub const DXVA2_E_VIDEO_DEVICE_LOCKED: ::windows_sys::core::HRESULT = -2147217406i32;
#[repr(C)]
pub struct DXVA2_ExtendedFormat {
    pub Anonymous: DXVA2_ExtendedFormat_0,
}
impl ::core::marker::Copy for DXVA2_ExtendedFormat {}
impl ::core::clone::Clone for DXVA2_ExtendedFormat {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union DXVA2_ExtendedFormat_0 {
    pub Anonymous: DXVA2_ExtendedFormat_0_0,
    pub value: u32,
}
impl ::core::marker::Copy for DXVA2_ExtendedFormat_0 {}
impl ::core::clone::Clone for DXVA2_ExtendedFormat_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA2_ExtendedFormat_0_0 {
    pub _bitfield: u32,
}
impl ::core::marker::Copy for DXVA2_ExtendedFormat_0_0 {}
impl ::core::clone::Clone for DXVA2_ExtendedFormat_0_0 {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA2_FilterType = i32;
pub const DXVA2_NoiseFilterLumaLevel: DXVA2_FilterType = 1i32;
pub const DXVA2_NoiseFilterLumaThreshold: DXVA2_FilterType = 2i32;
pub const DXVA2_NoiseFilterLumaRadius: DXVA2_FilterType = 3i32;
pub const DXVA2_NoiseFilterChromaLevel: DXVA2_FilterType = 4i32;
pub const DXVA2_NoiseFilterChromaThreshold: DXVA2_FilterType = 5i32;
pub const DXVA2_NoiseFilterChromaRadius: DXVA2_FilterType = 6i32;
pub const DXVA2_DetailFilterLumaLevel: DXVA2_FilterType = 7i32;
pub const DXVA2_DetailFilterLumaThreshold: DXVA2_FilterType = 8i32;
pub const DXVA2_DetailFilterLumaRadius: DXVA2_FilterType = 9i32;
pub const DXVA2_DetailFilterChromaLevel: DXVA2_FilterType = 10i32;
pub const DXVA2_DetailFilterChromaThreshold: DXVA2_FilterType = 11i32;
pub const DXVA2_DetailFilterChromaRadius: DXVA2_FilterType = 12i32;
#[repr(C)]
pub struct DXVA2_FilterValues {
    pub Level: DXVA2_Fixed32,
    pub Threshold: DXVA2_Fixed32,
    pub Radius: DXVA2_Fixed32,
}
impl ::core::marker::Copy for DXVA2_FilterValues {}
impl ::core::clone::Clone for DXVA2_FilterValues {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA2_Fixed32 {
    pub Anonymous: DXVA2_Fixed32_0,
}
impl ::core::marker::Copy for DXVA2_Fixed32 {}
impl ::core::clone::Clone for DXVA2_Fixed32 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union DXVA2_Fixed32_0 {
    pub Anonymous: DXVA2_Fixed32_0_0,
    pub ll: i32,
}
impl ::core::marker::Copy for DXVA2_Fixed32_0 {}
impl ::core::clone::Clone for DXVA2_Fixed32_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA2_Fixed32_0_0 {
    pub Fraction: u16,
    pub Value: i16,
}
impl ::core::marker::Copy for DXVA2_Fixed32_0_0 {}
impl ::core::clone::Clone for DXVA2_Fixed32_0_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA2_Frequency {
    pub Numerator: u32,
    pub Denominator: u32,
}
impl ::core::marker::Copy for DXVA2_Frequency {}
impl ::core::clone::Clone for DXVA2_Frequency {
    fn clone(&self) -> Self {
        *self
    }
}
pub const DXVA2_ModeH264_A: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487716, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeH264_B: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487717, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeH264_C: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487718, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeH264_D: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487719, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeH264_E: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487720, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeH264_F: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487721, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeH264_VLD_Multiview_NoFGT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1885052290,
    data2: 30415,
    data3: 18902,
    data4: [183, 230, 172, 136, 114, 219, 1, 60],
};
pub const DXVA2_ModeH264_VLD_Stereo_NoFGT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4188720315, data2: 49846, data3: 19708, data4: [135, 121, 87, 7, 177, 118, 5, 82] };
pub const DXVA2_ModeH264_VLD_Stereo_Progressive_NoFGT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3617319130, data2: 3313, data3: 19585, data4: [184, 42, 105, 164, 226, 54, 244, 61] };
pub const DXVA2_ModeH264_VLD_WithFMOASO_NoFGT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3589296121,
    data2: 13336,
    data3: 17880,
    data4: [149, 97, 50, 167, 106, 174, 45, 221],
};
pub const DXVA2_ModeHEVC_VLD_Main: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1527895323, data2: 12108, data3: 17490, data4: [188, 195, 9, 242, 161, 22, 12, 192] };
pub const DXVA2_ModeHEVC_VLD_Main10: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 276492512, data2: 61210, data3: 19737, data4: [171, 168, 103, 161, 99, 7, 61, 19] };
pub const DXVA2_ModeMPEG1_VLD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1866385177,
    data2: 14133,
    data3: 17100,
    data4: [128, 99, 101, 204, 60, 179, 102, 22],
};
pub const DXVA2_ModeMPEG2_IDCT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3206720768, data2: 1002, data3: 18064, data4: [128, 119, 71, 51, 70, 32, 155, 126] };
pub const DXVA2_ModeMPEG2_MoComp: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3869897803,
    data2: 25008,
    data3: 17763,
    data4: [158, 164, 99, 210, 163, 198, 254, 102],
};
pub const DXVA2_ModeMPEG2_VLD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3995550079, data2: 24104, data3: 20069, data4: [190, 234, 29, 38, 181, 8, 173, 201] };
pub const DXVA2_ModeMPEG2and1_VLD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2255052562,
    data2: 13326,
    data3: 20228,
    data4: [159, 211, 146, 83, 221, 50, 116, 96],
};
pub const DXVA2_ModeMPEG4pt2_VLD_AdvSimple_GMC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2878966619,
    data2: 16984,
    data3: 17577,
    data4: [159, 235, 148, 229, 151, 166, 186, 174],
};
pub const DXVA2_ModeMPEG4pt2_VLD_AdvSimple_NoGMC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3980495519, data2: 269, data3: 20186, data4: [154, 227, 154, 101, 53, 141, 141, 46] };
pub const DXVA2_ModeMPEG4pt2_VLD_Simple: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4023799156,
    data2: 51688,
    data3: 16855,
    data4: [165, 233, 233, 176, 227, 159, 163, 25],
};
pub const DXVA2_ModeVC1_A: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487776, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeVC1_B: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487777, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeVC1_C: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487778, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeVC1_D: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487779, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeVC1_D2010: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487780, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeVP8_VLD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2428017130,
    data2: 14946,
    data3: 18181,
    data4: [136, 179, 141, 240, 75, 39, 68, 231],
};
pub const DXVA2_ModeVP9_VLD_10bit_Profile2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2764524015, data2: 28367, data3: 18602, data4: [132, 72, 80, 167, 161, 22, 95, 247] };
pub const DXVA2_ModeVP9_VLD_Profile0: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1178011640,
    data2: 41424,
    data3: 17797,
    data4: [135, 109, 131, 170, 109, 96, 184, 158],
};
pub const DXVA2_ModeWMV8_A: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487744, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeWMV8_B: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487745, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeWMV9_A: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487760, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeWMV9_B: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487761, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_ModeWMV9_C: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487764, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVA2_NoEncrypt: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487824, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub type DXVA2_NoiseFilterTech = i32;
pub const DXVA2_NoiseFilterTech_Unsupported: DXVA2_NoiseFilterTech = 0i32;
pub const DXVA2_NoiseFilterTech_Unknown: DXVA2_NoiseFilterTech = 1i32;
pub const DXVA2_NoiseFilterTech_Median: DXVA2_NoiseFilterTech = 2i32;
pub const DXVA2_NoiseFilterTech_Temporal: DXVA2_NoiseFilterTech = 4i32;
pub const DXVA2_NoiseFilterTech_BlockNoise: DXVA2_NoiseFilterTech = 8i32;
pub const DXVA2_NoiseFilterTech_MosquitoNoise: DXVA2_NoiseFilterTech = 16i32;
pub const DXVA2_NoiseFilterTech_Mask: DXVA2_NoiseFilterTech = 31i32;
pub type DXVA2_NominalRange = i32;
pub const DXVA2_NominalRangeMask: DXVA2_NominalRange = 7i32;
pub const DXVA2_NominalRange_Unknown: DXVA2_NominalRange = 0i32;
pub const DXVA2_NominalRange_Normal: DXVA2_NominalRange = 1i32;
pub const DXVA2_NominalRange_Wide: DXVA2_NominalRange = 2i32;
pub const DXVA2_NominalRange_0_255: DXVA2_NominalRange = 1i32;
pub const DXVA2_NominalRange_16_235: DXVA2_NominalRange = 2i32;
pub const DXVA2_NominalRange_48_208: DXVA2_NominalRange = 3i32;
pub type DXVA2_ProcAmp = i32;
pub const DXVA2_ProcAmp_None: DXVA2_ProcAmp = 0i32;
pub const DXVA2_ProcAmp_Brightness: DXVA2_ProcAmp = 1i32;
pub const DXVA2_ProcAmp_Contrast: DXVA2_ProcAmp = 2i32;
pub const DXVA2_ProcAmp_Hue: DXVA2_ProcAmp = 4i32;
pub const DXVA2_ProcAmp_Saturation: DXVA2_ProcAmp = 8i32;
pub const DXVA2_ProcAmp_Mask: DXVA2_ProcAmp = 15i32;
#[repr(C)]
pub struct DXVA2_ProcAmpValues {
    pub Brightness: DXVA2_Fixed32,
    pub Contrast: DXVA2_Fixed32,
    pub Hue: DXVA2_Fixed32,
    pub Saturation: DXVA2_Fixed32,
}
impl ::core::marker::Copy for DXVA2_ProcAmpValues {}
impl ::core::clone::Clone for DXVA2_ProcAmpValues {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA2_SampleData = i32;
pub const DXVA2_SampleData_RFF: DXVA2_SampleData = 1i32;
pub const DXVA2_SampleData_TFF: DXVA2_SampleData = 2i32;
pub const DXVA2_SampleData_RFF_TFF_Present: DXVA2_SampleData = 4i32;
pub const DXVA2_SampleData_Mask: DXVA2_SampleData = 65535i32;
pub type DXVA2_SampleFormat = i32;
pub const DXVA2_SampleFormatMask: DXVA2_SampleFormat = 255i32;
pub const DXVA2_SampleUnknown: DXVA2_SampleFormat = 0i32;
pub const DXVA2_SampleProgressiveFrame: DXVA2_SampleFormat = 2i32;
pub const DXVA2_SampleFieldInterleavedEvenFirst: DXVA2_SampleFormat = 3i32;
pub const DXVA2_SampleFieldInterleavedOddFirst: DXVA2_SampleFormat = 4i32;
pub const DXVA2_SampleFieldSingleEven: DXVA2_SampleFormat = 5i32;
pub const DXVA2_SampleFieldSingleOdd: DXVA2_SampleFormat = 6i32;
pub const DXVA2_SampleSubStream: DXVA2_SampleFormat = 7i32;
pub type DXVA2_SurfaceType = i32;
pub const DXVA2_SurfaceType_DecoderRenderTarget: DXVA2_SurfaceType = 0i32;
pub const DXVA2_SurfaceType_ProcessorRenderTarget: DXVA2_SurfaceType = 1i32;
pub const DXVA2_SurfaceType_D3DRenderTargetTexture: DXVA2_SurfaceType = 2i32;
pub type DXVA2_VPDev = i32;
pub const DXVA2_VPDev_HardwareDevice: DXVA2_VPDev = 1i32;
pub const DXVA2_VPDev_EmulatedDXVA1: DXVA2_VPDev = 2i32;
pub const DXVA2_VPDev_SoftwareDevice: DXVA2_VPDev = 4i32;
pub const DXVA2_VPDev_Mask: DXVA2_VPDev = 7i32;
#[repr(C)]
pub struct DXVA2_ValueRange {
    pub MinValue: DXVA2_Fixed32,
    pub MaxValue: DXVA2_Fixed32,
    pub DefaultValue: DXVA2_Fixed32,
    pub StepSize: DXVA2_Fixed32,
}
impl ::core::marker::Copy for DXVA2_ValueRange {}
impl ::core::clone::Clone for DXVA2_ValueRange {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA2_VideoChromaSubSampling = i32;
pub const DXVA2_VideoChromaSubsamplingMask: DXVA2_VideoChromaSubSampling = 15i32;
pub const DXVA2_VideoChromaSubsampling_Unknown: DXVA2_VideoChromaSubSampling = 0i32;
pub const DXVA2_VideoChromaSubsampling_ProgressiveChroma: DXVA2_VideoChromaSubSampling = 8i32;
pub const DXVA2_VideoChromaSubsampling_Horizontally_Cosited: DXVA2_VideoChromaSubSampling = 4i32;
pub const DXVA2_VideoChromaSubsampling_Vertically_Cosited: DXVA2_VideoChromaSubSampling = 2i32;
pub const DXVA2_VideoChromaSubsampling_Vertically_AlignedChromaPlanes: DXVA2_VideoChromaSubSampling = 1i32;
pub const DXVA2_VideoChromaSubsampling_MPEG2: DXVA2_VideoChromaSubSampling = 5i32;
pub const DXVA2_VideoChromaSubsampling_MPEG1: DXVA2_VideoChromaSubSampling = 1i32;
pub const DXVA2_VideoChromaSubsampling_DV_PAL: DXVA2_VideoChromaSubSampling = 6i32;
pub const DXVA2_VideoChromaSubsampling_Cosited: DXVA2_VideoChromaSubSampling = 7i32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVA2_VideoDesc {
    pub SampleWidth: u32,
    pub SampleHeight: u32,
    pub SampleFormat: DXVA2_ExtendedFormat,
    pub Format: super::super::Graphics::Direct3D9::D3DFORMAT,
    pub InputSampleFreq: DXVA2_Frequency,
    pub OutputFrameFreq: DXVA2_Frequency,
    pub UABProtectionLevel: u32,
    pub Reserved: u32,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVA2_VideoDesc {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVA2_VideoDesc {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA2_VideoLighting = i32;
pub const DXVA2_VideoLightingMask: DXVA2_VideoLighting = 15i32;
pub const DXVA2_VideoLighting_Unknown: DXVA2_VideoLighting = 0i32;
pub const DXVA2_VideoLighting_bright: DXVA2_VideoLighting = 1i32;
pub const DXVA2_VideoLighting_office: DXVA2_VideoLighting = 2i32;
pub const DXVA2_VideoLighting_dim: DXVA2_VideoLighting = 3i32;
pub const DXVA2_VideoLighting_dark: DXVA2_VideoLighting = 4i32;
pub type DXVA2_VideoPrimaries = i32;
pub const DXVA2_VideoPrimariesMask: DXVA2_VideoPrimaries = 31i32;
pub const DXVA2_VideoPrimaries_Unknown: DXVA2_VideoPrimaries = 0i32;
pub const DXVA2_VideoPrimaries_reserved: DXVA2_VideoPrimaries = 1i32;
pub const DXVA2_VideoPrimaries_BT709: DXVA2_VideoPrimaries = 2i32;
pub const DXVA2_VideoPrimaries_BT470_2_SysM: DXVA2_VideoPrimaries = 3i32;
pub const DXVA2_VideoPrimaries_BT470_2_SysBG: DXVA2_VideoPrimaries = 4i32;
pub const DXVA2_VideoPrimaries_SMPTE170M: DXVA2_VideoPrimaries = 5i32;
pub const DXVA2_VideoPrimaries_SMPTE240M: DXVA2_VideoPrimaries = 6i32;
pub const DXVA2_VideoPrimaries_EBU3213: DXVA2_VideoPrimaries = 7i32;
pub const DXVA2_VideoPrimaries_SMPTE_C: DXVA2_VideoPrimaries = 8i32;
pub const DXVA2_VideoProcBobDevice: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 861578094,
    data2: 30852,
    data3: 17316,
    data4: [156, 145, 127, 135, 250, 243, 227, 126],
};
pub const DXVA2_VideoProcProgressiveDevice: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1515495625,
    data2: 51180,
    data3: 19417,
    data4: [142, 222, 243, 199, 93, 196, 57, 59],
};
pub const DXVA2_VideoProcSoftwareDevice: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1163121791,
    data2: 61054,
    data3: 20031,
    data4: [148, 117, 219, 241, 55, 108, 72, 16],
};
pub type DXVA2_VideoProcess = i32;
pub const DXVA2_VideoProcess_None: DXVA2_VideoProcess = 0i32;
pub const DXVA2_VideoProcess_YUV2RGB: DXVA2_VideoProcess = 1i32;
pub const DXVA2_VideoProcess_StretchX: DXVA2_VideoProcess = 2i32;
pub const DXVA2_VideoProcess_StretchY: DXVA2_VideoProcess = 4i32;
pub const DXVA2_VideoProcess_AlphaBlend: DXVA2_VideoProcess = 8i32;
pub const DXVA2_VideoProcess_SubRects: DXVA2_VideoProcess = 16i32;
pub const DXVA2_VideoProcess_SubStreams: DXVA2_VideoProcess = 32i32;
pub const DXVA2_VideoProcess_SubStreamsExtended: DXVA2_VideoProcess = 64i32;
pub const DXVA2_VideoProcess_YUV2RGBExtended: DXVA2_VideoProcess = 128i32;
pub const DXVA2_VideoProcess_AlphaBlendExtended: DXVA2_VideoProcess = 256i32;
pub const DXVA2_VideoProcess_Constriction: DXVA2_VideoProcess = 512i32;
pub const DXVA2_VideoProcess_NoiseFilter: DXVA2_VideoProcess = 1024i32;
pub const DXVA2_VideoProcess_DetailFilter: DXVA2_VideoProcess = 2048i32;
pub const DXVA2_VideoProcess_PlanarAlpha: DXVA2_VideoProcess = 4096i32;
pub const DXVA2_VideoProcess_LinearScaling: DXVA2_VideoProcess = 8192i32;
pub const DXVA2_VideoProcess_GammaCompensated: DXVA2_VideoProcess = 16384i32;
pub const DXVA2_VideoProcess_MaintainsOriginalFieldData: DXVA2_VideoProcess = 32768i32;
pub const DXVA2_VideoProcess_Mask: DXVA2_VideoProcess = 65535i32;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVA2_VideoProcessBltParams {
    pub TargetFrame: i64,
    pub TargetRect: super::super::Foundation::RECT,
    pub ConstrictionSize: super::super::Foundation::SIZE,
    pub StreamingFlags: u32,
    pub BackgroundColor: DXVA2_AYUVSample16,
    pub DestFormat: DXVA2_ExtendedFormat,
    pub ProcAmpValues: DXVA2_ProcAmpValues,
    pub Alpha: DXVA2_Fixed32,
    pub NoiseFilterLuma: DXVA2_FilterValues,
    pub NoiseFilterChroma: DXVA2_FilterValues,
    pub DetailFilterLuma: DXVA2_FilterValues,
    pub DetailFilterChroma: DXVA2_FilterValues,
    pub DestData: u32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVA2_VideoProcessBltParams {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVA2_VideoProcessBltParams {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVA2_VideoProcessorCaps {
    pub DeviceCaps: u32,
    pub InputPool: super::super::Graphics::Direct3D9::D3DPOOL,
    pub NumForwardRefSamples: u32,
    pub NumBackwardRefSamples: u32,
    pub Reserved: u32,
    pub DeinterlaceTechnology: u32,
    pub ProcAmpControlCaps: u32,
    pub VideoProcessorOperations: u32,
    pub NoiseFilterTechnology: u32,
    pub DetailFilterTechnology: u32,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVA2_VideoProcessorCaps {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVA2_VideoProcessorCaps {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA2_VideoRenderTargetType = i32;
pub const DXVA2_VideoDecoderRenderTarget: DXVA2_VideoRenderTargetType = 0i32;
pub const DXVA2_VideoProcessorRenderTarget: DXVA2_VideoRenderTargetType = 1i32;
pub const DXVA2_VideoSoftwareRenderTarget: DXVA2_VideoRenderTargetType = 2i32;
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub struct DXVA2_VideoSample {
    pub Start: i64,
    pub End: i64,
    pub SampleFormat: DXVA2_ExtendedFormat,
    pub SrcSurface: super::super::Graphics::Direct3D9::IDirect3DSurface9,
    pub SrcRect: super::super::Foundation::RECT,
    pub DstRect: super::super::Foundation::RECT,
    pub Pal: [DXVA2_AYUVSample8; 16],
    pub PlanarAlpha: DXVA2_Fixed32,
    pub SampleData: u32,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::marker::Copy for DXVA2_VideoSample {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::clone::Clone for DXVA2_VideoSample {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA2_VideoTransferFunction = i32;
pub const DXVA2_VideoTransFuncMask: DXVA2_VideoTransferFunction = 31i32;
pub const DXVA2_VideoTransFunc_Unknown: DXVA2_VideoTransferFunction = 0i32;
pub const DXVA2_VideoTransFunc_10: DXVA2_VideoTransferFunction = 1i32;
pub const DXVA2_VideoTransFunc_18: DXVA2_VideoTransferFunction = 2i32;
pub const DXVA2_VideoTransFunc_20: DXVA2_VideoTransferFunction = 3i32;
pub const DXVA2_VideoTransFunc_22: DXVA2_VideoTransferFunction = 4i32;
pub const DXVA2_VideoTransFunc_709: DXVA2_VideoTransferFunction = 5i32;
pub const DXVA2_VideoTransFunc_240M: DXVA2_VideoTransferFunction = 6i32;
pub const DXVA2_VideoTransFunc_sRGB: DXVA2_VideoTransferFunction = 7i32;
pub const DXVA2_VideoTransFunc_28: DXVA2_VideoTransferFunction = 8i32;
pub type DXVA2_VideoTransferMatrix = i32;
pub const DXVA2_VideoTransferMatrixMask: DXVA2_VideoTransferMatrix = 7i32;
pub const DXVA2_VideoTransferMatrix_Unknown: DXVA2_VideoTransferMatrix = 0i32;
pub const DXVA2_VideoTransferMatrix_BT709: DXVA2_VideoTransferMatrix = 1i32;
pub const DXVA2_VideoTransferMatrix_BT601: DXVA2_VideoTransferMatrix = 2i32;
pub const DXVA2_VideoTransferMatrix_SMPTE240M: DXVA2_VideoTransferMatrix = 3i32;
#[repr(C)]
pub struct DXVABufferInfo {
    pub pCompSurface: *mut ::core::ffi::c_void,
    pub DataOffset: u32,
    pub DataSize: u32,
}
impl ::core::marker::Copy for DXVABufferInfo {}
impl ::core::clone::Clone for DXVABufferInfo {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVACompBufferInfo {
    pub NumCompBuffers: u32,
    pub WidthToCreate: u32,
    pub HeightToCreate: u32,
    pub BytesToAllocate: u32,
    pub Usage: u32,
    pub Pool: super::super::Graphics::Direct3D9::D3DPOOL,
    pub Format: super::super::Graphics::Direct3D9::D3DFORMAT,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVACompBufferInfo {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVACompBufferInfo {
    fn clone(&self) -> Self {
        *self
    }
}
pub const DXVAHDControlGuid: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2688052853, data2: 63244, data3: 17996, data4: [169, 206, 51, 196, 78, 9, 22, 35] };
pub const DXVAHDETWGUID_CREATEVIDEOPROCESSOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1746812190, data2: 22132, data3: 20403, data4: [165, 3, 47, 32, 85, 233, 31, 96] };
pub const DXVAHDETWGUID_DESTROYVIDEOPROCESSOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4181979296,
    data2: 16150,
    data3: 17376,
    data4: [128, 147, 16, 90, 152, 106, 165, 241],
};
pub const DXVAHDETWGUID_VIDEOPROCESSBLTHD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3203650613, data2: 30919, data3: 19939, data4: [151, 7, 205, 27, 8, 59, 22, 10] };
pub const DXVAHDETWGUID_VIDEOPROCESSBLTHD_STREAM: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 665732926,
    data2: 42492,
    data3: 19429,
    data4: [180, 227, 242, 73, 148, 211, 196, 149],
};
pub const DXVAHDETWGUID_VIDEOPROCESSBLTSTATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1992903514,
    data2: 6463,
    data3: 18066,
    data4: [148, 132, 164, 217, 153, 218, 129, 168],
};
pub const DXVAHDETWGUID_VIDEOPROCESSSTREAMSTATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 640420610, data2: 8349, data3: 18413, data4: [148, 216, 130, 174, 2, 184, 74, 167] };
#[repr(C)]
pub struct DXVAHDETW_CREATEVIDEOPROCESSOR {
    pub pObject: u64,
    pub pD3D9Ex: u64,
    pub VPGuid: ::windows_sys::core::GUID,
}
impl ::core::marker::Copy for DXVAHDETW_CREATEVIDEOPROCESSOR {}
impl ::core::clone::Clone for DXVAHDETW_CREATEVIDEOPROCESSOR {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHDETW_DESTROYVIDEOPROCESSOR {
    pub pObject: u64,
}
impl ::core::marker::Copy for DXVAHDETW_DESTROYVIDEOPROCESSOR {}
impl ::core::clone::Clone for DXVAHDETW_DESTROYVIDEOPROCESSOR {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub struct DXVAHDETW_VIDEOPROCESSBLTHD {
    pub pObject: u64,
    pub pOutputSurface: u64,
    pub TargetRect: super::super::Foundation::RECT,
    pub OutputFormat: super::super::Graphics::Direct3D9::D3DFORMAT,
    pub ColorSpace: u32,
    pub OutputFrame: u32,
    pub StreamCount: u32,
    pub Enter: super::super::Foundation::BOOL,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::marker::Copy for DXVAHDETW_VIDEOPROCESSBLTHD {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::clone::Clone for DXVAHDETW_VIDEOPROCESSBLTHD {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub struct DXVAHDETW_VIDEOPROCESSBLTHD_STREAM {
    pub pObject: u64,
    pub pInputSurface: u64,
    pub SourceRect: super::super::Foundation::RECT,
    pub DestinationRect: super::super::Foundation::RECT,
    pub InputFormat: super::super::Graphics::Direct3D9::D3DFORMAT,
    pub FrameFormat: DXVAHD_FRAME_FORMAT,
    pub ColorSpace: u32,
    pub StreamNumber: u32,
    pub OutputIndex: u32,
    pub InputFrameOrField: u32,
    pub PastFrames: u32,
    pub FutureFrames: u32,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::marker::Copy for DXVAHDETW_VIDEOPROCESSBLTHD_STREAM {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::clone::Clone for DXVAHDETW_VIDEOPROCESSBLTHD_STREAM {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHDETW_VIDEOPROCESSBLTSTATE {
    pub pObject: u64,
    pub State: DXVAHD_BLT_STATE,
    pub DataSize: u32,
    pub SetState: super::super::Foundation::BOOL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHDETW_VIDEOPROCESSBLTSTATE {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHDETW_VIDEOPROCESSBLTSTATE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHDETW_VIDEOPROCESSSTREAMSTATE {
    pub pObject: u64,
    pub StreamNumber: u32,
    pub State: DXVAHD_STREAM_STATE,
    pub DataSize: u32,
    pub SetState: super::super::Foundation::BOOL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHDETW_VIDEOPROCESSSTREAMSTATE {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHDETW_VIDEOPROCESSSTREAMSTATE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub struct DXVAHDSW_CALLBACKS {
    pub CreateDevice: PDXVAHDSW_CreateDevice,
    pub ProposeVideoPrivateFormat: PDXVAHDSW_ProposeVideoPrivateFormat,
    pub GetVideoProcessorDeviceCaps: PDXVAHDSW_GetVideoProcessorDeviceCaps,
    pub GetVideoProcessorOutputFormats: PDXVAHDSW_GetVideoProcessorOutputFormats,
    pub GetVideoProcessorInputFormats: PDXVAHDSW_GetVideoProcessorInputFormats,
    pub GetVideoProcessorCaps: PDXVAHDSW_GetVideoProcessorCaps,
    pub GetVideoProcessorCustomRates: PDXVAHDSW_GetVideoProcessorCustomRates,
    pub GetVideoProcessorFilterRange: PDXVAHDSW_GetVideoProcessorFilterRange,
    pub DestroyDevice: PDXVAHDSW_DestroyDevice,
    pub CreateVideoProcessor: PDXVAHDSW_CreateVideoProcessor,
    pub SetVideoProcessBltState: PDXVAHDSW_SetVideoProcessBltState,
    pub GetVideoProcessBltStatePrivate: PDXVAHDSW_GetVideoProcessBltStatePrivate,
    pub SetVideoProcessStreamState: PDXVAHDSW_SetVideoProcessStreamState,
    pub GetVideoProcessStreamStatePrivate: PDXVAHDSW_GetVideoProcessStreamStatePrivate,
    pub VideoProcessBltHD: PDXVAHDSW_VideoProcessBltHD,
    pub DestroyVideoProcessor: PDXVAHDSW_DestroyVideoProcessor,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::marker::Copy for DXVAHDSW_CALLBACKS {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::clone::Clone for DXVAHDSW_CALLBACKS {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVAHD_ALPHA_FILL_MODE = i32;
pub const DXVAHD_ALPHA_FILL_MODE_OPAQUE: DXVAHD_ALPHA_FILL_MODE = 0i32;
pub const DXVAHD_ALPHA_FILL_MODE_BACKGROUND: DXVAHD_ALPHA_FILL_MODE = 1i32;
pub const DXVAHD_ALPHA_FILL_MODE_DESTINATION: DXVAHD_ALPHA_FILL_MODE = 2i32;
pub const DXVAHD_ALPHA_FILL_MODE_SOURCE_STREAM: DXVAHD_ALPHA_FILL_MODE = 3i32;
pub type DXVAHD_BLT_STATE = i32;
pub const DXVAHD_BLT_STATE_TARGET_RECT: DXVAHD_BLT_STATE = 0i32;
pub const DXVAHD_BLT_STATE_BACKGROUND_COLOR: DXVAHD_BLT_STATE = 1i32;
pub const DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE: DXVAHD_BLT_STATE = 2i32;
pub const DXVAHD_BLT_STATE_ALPHA_FILL: DXVAHD_BLT_STATE = 3i32;
pub const DXVAHD_BLT_STATE_CONSTRICTION: DXVAHD_BLT_STATE = 4i32;
pub const DXVAHD_BLT_STATE_PRIVATE: DXVAHD_BLT_STATE = 1000i32;
#[repr(C)]
pub struct DXVAHD_BLT_STATE_ALPHA_FILL_DATA {
    pub Mode: DXVAHD_ALPHA_FILL_MODE,
    pub StreamNumber: u32,
}
impl ::core::marker::Copy for DXVAHD_BLT_STATE_ALPHA_FILL_DATA {}
impl ::core::clone::Clone for DXVAHD_BLT_STATE_ALPHA_FILL_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_BLT_STATE_BACKGROUND_COLOR_DATA {
    pub YCbCr: super::super::Foundation::BOOL,
    pub BackgroundColor: DXVAHD_COLOR,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_BLT_STATE_BACKGROUND_COLOR_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_BLT_STATE_BACKGROUND_COLOR_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_BLT_STATE_CONSTRICTION_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub Size: super::super::Foundation::SIZE,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_BLT_STATE_CONSTRICTION_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_BLT_STATE_CONSTRICTION_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA {
    pub Anonymous: DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA_0,
}
impl ::core::marker::Copy for DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA {}
impl ::core::clone::Clone for DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA_0 {
    pub Anonymous: DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA_0_0,
    pub Value: u32,
}
impl ::core::marker::Copy for DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA_0 {}
impl ::core::clone::Clone for DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA_0_0 {
    pub _bitfield: u32,
}
impl ::core::marker::Copy for DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA_0_0 {}
impl ::core::clone::Clone for DXVAHD_BLT_STATE_OUTPUT_COLOR_SPACE_DATA_0_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_BLT_STATE_PRIVATE_DATA {
    pub Guid: ::windows_sys::core::GUID,
    pub DataSize: u32,
    pub pData: *mut ::core::ffi::c_void,
}
impl ::core::marker::Copy for DXVAHD_BLT_STATE_PRIVATE_DATA {}
impl ::core::clone::Clone for DXVAHD_BLT_STATE_PRIVATE_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_BLT_STATE_TARGET_RECT_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub TargetRect: super::super::Foundation::RECT,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_BLT_STATE_TARGET_RECT_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_BLT_STATE_TARGET_RECT_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union DXVAHD_COLOR {
    pub RGB: DXVAHD_COLOR_RGBA,
    pub YCbCr: DXVAHD_COLOR_YCbCrA,
}
impl ::core::marker::Copy for DXVAHD_COLOR {}
impl ::core::clone::Clone for DXVAHD_COLOR {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_COLOR_RGBA {
    pub R: f32,
    pub G: f32,
    pub B: f32,
    pub A: f32,
}
impl ::core::marker::Copy for DXVAHD_COLOR_RGBA {}
impl ::core::clone::Clone for DXVAHD_COLOR_RGBA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_COLOR_YCbCrA {
    pub Y: f32,
    pub Cb: f32,
    pub Cr: f32,
    pub A: f32,
}
impl ::core::marker::Copy for DXVAHD_COLOR_YCbCrA {}
impl ::core::clone::Clone for DXVAHD_COLOR_YCbCrA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_CONTENT_DESC {
    pub InputFrameFormat: DXVAHD_FRAME_FORMAT,
    pub InputFrameRate: DXVAHD_RATIONAL,
    pub InputWidth: u32,
    pub InputHeight: u32,
    pub OutputFrameRate: DXVAHD_RATIONAL,
    pub OutputWidth: u32,
    pub OutputHeight: u32,
}
impl ::core::marker::Copy for DXVAHD_CONTENT_DESC {}
impl ::core::clone::Clone for DXVAHD_CONTENT_DESC {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_CUSTOM_RATE_DATA {
    pub CustomRate: DXVAHD_RATIONAL,
    pub OutputFrames: u32,
    pub InputInterlaced: super::super::Foundation::BOOL,
    pub InputFramesOrFields: u32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_CUSTOM_RATE_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_CUSTOM_RATE_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVAHD_DEVICE_CAPS = i32;
pub const DXVAHD_DEVICE_CAPS_LINEAR_SPACE: DXVAHD_DEVICE_CAPS = 1i32;
pub const DXVAHD_DEVICE_CAPS_xvYCC: DXVAHD_DEVICE_CAPS = 2i32;
pub const DXVAHD_DEVICE_CAPS_RGB_RANGE_CONVERSION: DXVAHD_DEVICE_CAPS = 4i32;
pub const DXVAHD_DEVICE_CAPS_YCbCr_MATRIX_CONVERSION: DXVAHD_DEVICE_CAPS = 8i32;
pub type DXVAHD_DEVICE_TYPE = i32;
pub const DXVAHD_DEVICE_TYPE_HARDWARE: DXVAHD_DEVICE_TYPE = 0i32;
pub const DXVAHD_DEVICE_TYPE_SOFTWARE: DXVAHD_DEVICE_TYPE = 1i32;
pub const DXVAHD_DEVICE_TYPE_REFERENCE: DXVAHD_DEVICE_TYPE = 2i32;
pub const DXVAHD_DEVICE_TYPE_OTHER: DXVAHD_DEVICE_TYPE = 3i32;
pub type DXVAHD_DEVICE_USAGE = i32;
pub const DXVAHD_DEVICE_USAGE_PLAYBACK_NORMAL: DXVAHD_DEVICE_USAGE = 0i32;
pub const DXVAHD_DEVICE_USAGE_OPTIMAL_SPEED: DXVAHD_DEVICE_USAGE = 1i32;
pub const DXVAHD_DEVICE_USAGE_OPTIMAL_QUALITY: DXVAHD_DEVICE_USAGE = 2i32;
pub type DXVAHD_FEATURE_CAPS = i32;
pub const DXVAHD_FEATURE_CAPS_ALPHA_FILL: DXVAHD_FEATURE_CAPS = 1i32;
pub const DXVAHD_FEATURE_CAPS_CONSTRICTION: DXVAHD_FEATURE_CAPS = 2i32;
pub const DXVAHD_FEATURE_CAPS_LUMA_KEY: DXVAHD_FEATURE_CAPS = 4i32;
pub const DXVAHD_FEATURE_CAPS_ALPHA_PALETTE: DXVAHD_FEATURE_CAPS = 8i32;
pub type DXVAHD_FILTER = i32;
pub const DXVAHD_FILTER_BRIGHTNESS: DXVAHD_FILTER = 0i32;
pub const DXVAHD_FILTER_CONTRAST: DXVAHD_FILTER = 1i32;
pub const DXVAHD_FILTER_HUE: DXVAHD_FILTER = 2i32;
pub const DXVAHD_FILTER_SATURATION: DXVAHD_FILTER = 3i32;
pub const DXVAHD_FILTER_NOISE_REDUCTION: DXVAHD_FILTER = 4i32;
pub const DXVAHD_FILTER_EDGE_ENHANCEMENT: DXVAHD_FILTER = 5i32;
pub const DXVAHD_FILTER_ANAMORPHIC_SCALING: DXVAHD_FILTER = 6i32;
pub type DXVAHD_FILTER_CAPS = i32;
pub const DXVAHD_FILTER_CAPS_BRIGHTNESS: DXVAHD_FILTER_CAPS = 1i32;
pub const DXVAHD_FILTER_CAPS_CONTRAST: DXVAHD_FILTER_CAPS = 2i32;
pub const DXVAHD_FILTER_CAPS_HUE: DXVAHD_FILTER_CAPS = 4i32;
pub const DXVAHD_FILTER_CAPS_SATURATION: DXVAHD_FILTER_CAPS = 8i32;
pub const DXVAHD_FILTER_CAPS_NOISE_REDUCTION: DXVAHD_FILTER_CAPS = 16i32;
pub const DXVAHD_FILTER_CAPS_EDGE_ENHANCEMENT: DXVAHD_FILTER_CAPS = 32i32;
pub const DXVAHD_FILTER_CAPS_ANAMORPHIC_SCALING: DXVAHD_FILTER_CAPS = 64i32;
#[repr(C)]
pub struct DXVAHD_FILTER_RANGE_DATA {
    pub Minimum: i32,
    pub Maximum: i32,
    pub Default: i32,
    pub Multiplier: f32,
}
impl ::core::marker::Copy for DXVAHD_FILTER_RANGE_DATA {}
impl ::core::clone::Clone for DXVAHD_FILTER_RANGE_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVAHD_FRAME_FORMAT = i32;
pub const DXVAHD_FRAME_FORMAT_PROGRESSIVE: DXVAHD_FRAME_FORMAT = 0i32;
pub const DXVAHD_FRAME_FORMAT_INTERLACED_TOP_FIELD_FIRST: DXVAHD_FRAME_FORMAT = 1i32;
pub const DXVAHD_FRAME_FORMAT_INTERLACED_BOTTOM_FIELD_FIRST: DXVAHD_FRAME_FORMAT = 2i32;
pub type DXVAHD_INPUT_FORMAT_CAPS = i32;
pub const DXVAHD_INPUT_FORMAT_CAPS_RGB_INTERLACED: DXVAHD_INPUT_FORMAT_CAPS = 1i32;
pub const DXVAHD_INPUT_FORMAT_CAPS_RGB_PROCAMP: DXVAHD_INPUT_FORMAT_CAPS = 2i32;
pub const DXVAHD_INPUT_FORMAT_CAPS_RGB_LUMA_KEY: DXVAHD_INPUT_FORMAT_CAPS = 4i32;
pub const DXVAHD_INPUT_FORMAT_CAPS_PALETTE_INTERLACED: DXVAHD_INPUT_FORMAT_CAPS = 8i32;
pub type DXVAHD_ITELECINE_CAPS = i32;
pub const DXVAHD_ITELECINE_CAPS_32: DXVAHD_ITELECINE_CAPS = 1i32;
pub const DXVAHD_ITELECINE_CAPS_22: DXVAHD_ITELECINE_CAPS = 2i32;
pub const DXVAHD_ITELECINE_CAPS_2224: DXVAHD_ITELECINE_CAPS = 4i32;
pub const DXVAHD_ITELECINE_CAPS_2332: DXVAHD_ITELECINE_CAPS = 8i32;
pub const DXVAHD_ITELECINE_CAPS_32322: DXVAHD_ITELECINE_CAPS = 16i32;
pub const DXVAHD_ITELECINE_CAPS_55: DXVAHD_ITELECINE_CAPS = 32i32;
pub const DXVAHD_ITELECINE_CAPS_64: DXVAHD_ITELECINE_CAPS = 64i32;
pub const DXVAHD_ITELECINE_CAPS_87: DXVAHD_ITELECINE_CAPS = 128i32;
pub const DXVAHD_ITELECINE_CAPS_222222222223: DXVAHD_ITELECINE_CAPS = 256i32;
pub const DXVAHD_ITELECINE_CAPS_OTHER: DXVAHD_ITELECINE_CAPS = -2147483648i32;
pub type DXVAHD_OUTPUT_RATE = i32;
pub const DXVAHD_OUTPUT_RATE_NORMAL: DXVAHD_OUTPUT_RATE = 0i32;
pub const DXVAHD_OUTPUT_RATE_HALF: DXVAHD_OUTPUT_RATE = 1i32;
pub const DXVAHD_OUTPUT_RATE_CUSTOM: DXVAHD_OUTPUT_RATE = 2i32;
pub type DXVAHD_PROCESSOR_CAPS = i32;
pub const DXVAHD_PROCESSOR_CAPS_DEINTERLACE_BLEND: DXVAHD_PROCESSOR_CAPS = 1i32;
pub const DXVAHD_PROCESSOR_CAPS_DEINTERLACE_BOB: DXVAHD_PROCESSOR_CAPS = 2i32;
pub const DXVAHD_PROCESSOR_CAPS_DEINTERLACE_ADAPTIVE: DXVAHD_PROCESSOR_CAPS = 4i32;
pub const DXVAHD_PROCESSOR_CAPS_DEINTERLACE_MOTION_COMPENSATION: DXVAHD_PROCESSOR_CAPS = 8i32;
pub const DXVAHD_PROCESSOR_CAPS_INVERSE_TELECINE: DXVAHD_PROCESSOR_CAPS = 16i32;
pub const DXVAHD_PROCESSOR_CAPS_FRAME_RATE_CONVERSION: DXVAHD_PROCESSOR_CAPS = 32i32;
#[repr(C)]
pub struct DXVAHD_RATIONAL {
    pub Numerator: u32,
    pub Denominator: u32,
}
impl ::core::marker::Copy for DXVAHD_RATIONAL {}
impl ::core::clone::Clone for DXVAHD_RATIONAL {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub struct DXVAHD_STREAM_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub OutputIndex: u32,
    pub InputFrameOrField: u32,
    pub PastFrames: u32,
    pub FutureFrames: u32,
    pub ppPastSurfaces: *mut super::super::Graphics::Direct3D9::IDirect3DSurface9,
    pub pInputSurface: super::super::Graphics::Direct3D9::IDirect3DSurface9,
    pub ppFutureSurfaces: *mut super::super::Graphics::Direct3D9::IDirect3DSurface9,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::marker::Copy for DXVAHD_STREAM_DATA {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
impl ::core::clone::Clone for DXVAHD_STREAM_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVAHD_STREAM_STATE = i32;
pub const DXVAHD_STREAM_STATE_D3DFORMAT: DXVAHD_STREAM_STATE = 0i32;
pub const DXVAHD_STREAM_STATE_FRAME_FORMAT: DXVAHD_STREAM_STATE = 1i32;
pub const DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE: DXVAHD_STREAM_STATE = 2i32;
pub const DXVAHD_STREAM_STATE_OUTPUT_RATE: DXVAHD_STREAM_STATE = 3i32;
pub const DXVAHD_STREAM_STATE_SOURCE_RECT: DXVAHD_STREAM_STATE = 4i32;
pub const DXVAHD_STREAM_STATE_DESTINATION_RECT: DXVAHD_STREAM_STATE = 5i32;
pub const DXVAHD_STREAM_STATE_ALPHA: DXVAHD_STREAM_STATE = 6i32;
pub const DXVAHD_STREAM_STATE_PALETTE: DXVAHD_STREAM_STATE = 7i32;
pub const DXVAHD_STREAM_STATE_LUMA_KEY: DXVAHD_STREAM_STATE = 8i32;
pub const DXVAHD_STREAM_STATE_ASPECT_RATIO: DXVAHD_STREAM_STATE = 9i32;
pub const DXVAHD_STREAM_STATE_FILTER_BRIGHTNESS: DXVAHD_STREAM_STATE = 100i32;
pub const DXVAHD_STREAM_STATE_FILTER_CONTRAST: DXVAHD_STREAM_STATE = 101i32;
pub const DXVAHD_STREAM_STATE_FILTER_HUE: DXVAHD_STREAM_STATE = 102i32;
pub const DXVAHD_STREAM_STATE_FILTER_SATURATION: DXVAHD_STREAM_STATE = 103i32;
pub const DXVAHD_STREAM_STATE_FILTER_NOISE_REDUCTION: DXVAHD_STREAM_STATE = 104i32;
pub const DXVAHD_STREAM_STATE_FILTER_EDGE_ENHANCEMENT: DXVAHD_STREAM_STATE = 105i32;
pub const DXVAHD_STREAM_STATE_FILTER_ANAMORPHIC_SCALING: DXVAHD_STREAM_STATE = 106i32;
pub const DXVAHD_STREAM_STATE_PRIVATE: DXVAHD_STREAM_STATE = 1000i32;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_STREAM_STATE_ALPHA_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub Alpha: f32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_ALPHA_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_ALPHA_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_STREAM_STATE_ASPECT_RATIO_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub SourceAspectRatio: DXVAHD_RATIONAL,
    pub DestinationAspectRatio: DXVAHD_RATIONAL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_ASPECT_RATIO_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_ASPECT_RATIO_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVAHD_STREAM_STATE_D3DFORMAT_DATA {
    pub Format: super::super::Graphics::Direct3D9::D3DFORMAT,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_D3DFORMAT_DATA {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_D3DFORMAT_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_STREAM_STATE_DESTINATION_RECT_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub DestinationRect: super::super::Foundation::RECT,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_DESTINATION_RECT_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_DESTINATION_RECT_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_STREAM_STATE_FILTER_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub Level: i32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_FILTER_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_FILTER_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_STREAM_STATE_FRAME_FORMAT_DATA {
    pub FrameFormat: DXVAHD_FRAME_FORMAT,
}
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_FRAME_FORMAT_DATA {}
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_FRAME_FORMAT_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA {
    pub Anonymous: DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA_0,
}
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA {}
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA_0 {
    pub Anonymous: DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA_0_0,
    pub Value: u32,
}
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA_0 {}
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA_0_0 {
    pub _bitfield: u32,
}
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA_0_0 {}
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_INPUT_COLOR_SPACE_DATA_0_0 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_STREAM_STATE_LUMA_KEY_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub Lower: f32,
    pub Upper: f32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_LUMA_KEY_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_LUMA_KEY_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_STREAM_STATE_OUTPUT_RATE_DATA {
    pub RepeatFrame: super::super::Foundation::BOOL,
    pub OutputRate: DXVAHD_OUTPUT_RATE,
    pub CustomRate: DXVAHD_RATIONAL,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_OUTPUT_RATE_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_OUTPUT_RATE_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_STREAM_STATE_PALETTE_DATA {
    pub Count: u32,
    pub pEntries: *mut u32,
}
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_PALETTE_DATA {}
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_PALETTE_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVAHD_STREAM_STATE_PRIVATE_DATA {
    pub Guid: ::windows_sys::core::GUID,
    pub DataSize: u32,
    pub pData: *mut ::core::ffi::c_void,
}
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_PRIVATE_DATA {}
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_PRIVATE_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
pub const DXVAHD_STREAM_STATE_PRIVATE_IVTC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2623544892, data2: 3891, data3: 16716, data4: [167, 57, 153, 84, 14, 228, 45, 165] };
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_STREAM_STATE_PRIVATE_IVTC_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub ITelecineFlags: u32,
    pub Frames: u32,
    pub InputField: u32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_PRIVATE_IVTC_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_PRIVATE_IVTC_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVAHD_STREAM_STATE_SOURCE_RECT_DATA {
    pub Enable: super::super::Foundation::BOOL,
    pub SourceRect: super::super::Foundation::RECT,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVAHD_STREAM_STATE_SOURCE_RECT_DATA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVAHD_STREAM_STATE_SOURCE_RECT_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVAHD_SURFACE_TYPE = i32;
pub const DXVAHD_SURFACE_TYPE_VIDEO_INPUT: DXVAHD_SURFACE_TYPE = 0i32;
pub const DXVAHD_SURFACE_TYPE_VIDEO_INPUT_PRIVATE: DXVAHD_SURFACE_TYPE = 1i32;
pub const DXVAHD_SURFACE_TYPE_VIDEO_OUTPUT: DXVAHD_SURFACE_TYPE = 2i32;
#[repr(C)]
pub struct DXVAHD_VPCAPS {
    pub VPGuid: ::windows_sys::core::GUID,
    pub PastFrames: u32,
    pub FutureFrames: u32,
    pub ProcessorCaps: u32,
    pub ITelecineCaps: u32,
    pub CustomRateCount: u32,
}
impl ::core::marker::Copy for DXVAHD_VPCAPS {}
impl ::core::clone::Clone for DXVAHD_VPCAPS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVAHD_VPDEVCAPS {
    pub DeviceType: DXVAHD_DEVICE_TYPE,
    pub DeviceCaps: u32,
    pub FeatureCaps: u32,
    pub FilterCaps: u32,
    pub InputFormatCaps: u32,
    pub InputPool: super::super::Graphics::Direct3D9::D3DPOOL,
    pub OutputFormatCount: u32,
    pub InputFormatCount: u32,
    pub VideoProcessorCount: u32,
    pub MaxInputStreams: u32,
    pub MaxStreamStates: u32,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVAHD_VPDEVCAPS {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVAHD_VPDEVCAPS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVAUncompDataInfo {
    pub UncompWidth: u32,
    pub UncompHeight: u32,
    pub UncompFormat: super::super::Graphics::Direct3D9::D3DFORMAT,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVAUncompDataInfo {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVAUncompDataInfo {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA_AYUVsample2 {
    pub bCrValue: u8,
    pub bCbValue: u8,
    pub bY_Value: u8,
    pub bSampleAlpha8: u8,
}
impl ::core::marker::Copy for DXVA_AYUVsample2 {}
impl ::core::clone::Clone for DXVA_AYUVsample2 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C, packed(1))]
pub struct DXVA_BufferDescription {
    pub dwTypeIndex: u32,
    pub dwBufferIndex: u32,
    pub dwDataOffset: u32,
    pub dwDataSize: u32,
    pub dwFirstMBaddress: u32,
    pub dwNumMBsInBuffer: u32,
    pub dwWidth: u32,
    pub dwHeight: u32,
    pub dwStride: u32,
    pub dwReservedBits: u32,
}
impl ::core::marker::Copy for DXVA_BufferDescription {}
impl ::core::clone::Clone for DXVA_BufferDescription {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA_COPPCommand {
    pub macKDI: ::windows_sys::core::GUID,
    pub guidCommandID: ::windows_sys::core::GUID,
    pub dwSequence: u32,
    pub cbSizeData: u32,
    pub CommandData: [u8; 4056],
}
impl ::core::marker::Copy for DXVA_COPPCommand {}
impl ::core::clone::Clone for DXVA_COPPCommand {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA_COPPSignature {
    pub Signature: [u8; 256],
}
impl ::core::marker::Copy for DXVA_COPPSignature {}
impl ::core::clone::Clone for DXVA_COPPSignature {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA_COPPStatusInput {
    pub rApp: ::windows_sys::core::GUID,
    pub guidStatusRequestID: ::windows_sys::core::GUID,
    pub dwSequence: u32,
    pub cbSizeData: u32,
    pub StatusData: [u8; 4056],
}
impl ::core::marker::Copy for DXVA_COPPStatusInput {}
impl ::core::clone::Clone for DXVA_COPPStatusInput {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA_COPPStatusOutput {
    pub macKDI: ::windows_sys::core::GUID,
    pub cbSizeData: u32,
    pub COPPStatus: [u8; 4076],
}
impl ::core::marker::Copy for DXVA_COPPStatusOutput {}
impl ::core::clone::Clone for DXVA_COPPStatusOutput {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C, packed(1))]
pub struct DXVA_ConfigPictureDecode {
    pub dwFunction: u32,
    pub dwReservedBits: [u32; 3],
    pub guidConfigBitstreamEncryption: ::windows_sys::core::GUID,
    pub guidConfigMBcontrolEncryption: ::windows_sys::core::GUID,
    pub guidConfigResidDiffEncryption: ::windows_sys::core::GUID,
    pub bConfigBitstreamRaw: u8,
    pub bConfigMBcontrolRasterOrder: u8,
    pub bConfigResidDiffHost: u8,
    pub bConfigSpatialResid8: u8,
    pub bConfigResid8Subtraction: u8,
    pub bConfigSpatialHost8or9Clipping: u8,
    pub bConfigSpatialResidInterleaved: u8,
    pub bConfigIntraResidUnsigned: u8,
    pub bConfigResidDiffAccelerator: u8,
    pub bConfigHostInverseScan: u8,
    pub bConfigSpecificIDCT: u8,
    pub bConfig4GroupedCoefs: u8,
}
impl ::core::marker::Copy for DXVA_ConfigPictureDecode {}
impl ::core::clone::Clone for DXVA_ConfigPictureDecode {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVA_DeinterlaceBlt {
    pub Size: u32,
    pub Reserved: u32,
    pub rtTarget: i64,
    pub DstRect: super::super::Foundation::RECT,
    pub SrcRect: super::super::Foundation::RECT,
    pub NumSourceSurfaces: u32,
    pub Alpha: f32,
    pub Source: [DXVA_VideoSample; 32],
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVA_DeinterlaceBlt {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVA_DeinterlaceBlt {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVA_DeinterlaceBltEx {
    pub Size: u32,
    pub BackgroundColor: DXVA_AYUVsample2,
    pub rcTarget: super::super::Foundation::RECT,
    pub rtTarget: i64,
    pub NumSourceSurfaces: u32,
    pub Alpha: f32,
    pub Source: [DXVA_VideoSample2; 32],
    pub DestinationFormat: u32,
    pub DestinationFlags: u32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVA_DeinterlaceBltEx {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVA_DeinterlaceBltEx {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVA_DeinterlaceBltEx32 {
    pub Size: u32,
    pub BackgroundColor: DXVA_AYUVsample2,
    pub rcTarget: super::super::Foundation::RECT,
    pub rtTarget: i64,
    pub NumSourceSurfaces: u32,
    pub Alpha: f32,
    pub Source: [DXVA_VideoSample32; 32],
    pub DestinationFormat: u32,
    pub DestinationFlags: u32,
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVA_DeinterlaceBltEx32 {}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVA_DeinterlaceBltEx32 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVA_DeinterlaceCaps {
    pub Size: u32,
    pub NumPreviousOutputFrames: u32,
    pub InputPool: u32,
    pub NumForwardRefSamples: u32,
    pub NumBackwardRefSamples: u32,
    pub d3dOutputFormat: super::super::Graphics::Direct3D9::D3DFORMAT,
    pub VideoProcessingCaps: DXVA_VideoProcessCaps,
    pub DeinterlaceTechnology: DXVA_DeinterlaceTech,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVA_DeinterlaceCaps {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVA_DeinterlaceCaps {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA_DeinterlaceQueryAvailableModes {
    pub Size: u32,
    pub NumGuids: u32,
    pub Guids: [::windows_sys::core::GUID; 32],
}
impl ::core::marker::Copy for DXVA_DeinterlaceQueryAvailableModes {}
impl ::core::clone::Clone for DXVA_DeinterlaceQueryAvailableModes {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVA_DeinterlaceQueryModeCaps {
    pub Size: u32,
    pub Guid: ::windows_sys::core::GUID,
    pub VideoDesc: DXVA_VideoDesc,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVA_DeinterlaceQueryModeCaps {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVA_DeinterlaceQueryModeCaps {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA_DeinterlaceTech = i32;
pub const DXVA_DeinterlaceTech_Unknown: DXVA_DeinterlaceTech = 0i32;
pub const DXVA_DeinterlaceTech_BOBLineReplicate: DXVA_DeinterlaceTech = 1i32;
pub const DXVA_DeinterlaceTech_BOBVerticalStretch: DXVA_DeinterlaceTech = 2i32;
pub const DXVA_DeinterlaceTech_BOBVerticalStretch4Tap: DXVA_DeinterlaceTech = 256i32;
pub const DXVA_DeinterlaceTech_MedianFiltering: DXVA_DeinterlaceTech = 4i32;
pub const DXVA_DeinterlaceTech_EdgeFiltering: DXVA_DeinterlaceTech = 16i32;
pub const DXVA_DeinterlaceTech_FieldAdaptive: DXVA_DeinterlaceTech = 32i32;
pub const DXVA_DeinterlaceTech_PixelAdaptive: DXVA_DeinterlaceTech = 64i32;
pub const DXVA_DeinterlaceTech_MotionVectorSteered: DXVA_DeinterlaceTech = 128i32;
pub type DXVA_DestinationFlags = i32;
pub const DXVA_DestinationFlagMask: DXVA_DestinationFlags = 15i32;
pub const DXVA_DestinationFlag_Background_Changed: DXVA_DestinationFlags = 1i32;
pub const DXVA_DestinationFlag_TargetRect_Changed: DXVA_DestinationFlags = 2i32;
pub const DXVA_DestinationFlag_ColorData_Changed: DXVA_DestinationFlags = 4i32;
pub const DXVA_DestinationFlag_Alpha_Changed: DXVA_DestinationFlags = 8i32;
#[repr(C)]
pub struct DXVA_ExtendedFormat {
    pub _bitfield: u32,
}
impl ::core::marker::Copy for DXVA_ExtendedFormat {}
impl ::core::clone::Clone for DXVA_ExtendedFormat {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA_Frequency {
    pub Numerator: u32,
    pub Denominator: u32,
}
impl ::core::marker::Copy for DXVA_Frequency {}
impl ::core::clone::Clone for DXVA_Frequency {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA_NominalRange = i32;
pub const DXVA_NominalRangeShift: DXVA_NominalRange = 12i32;
pub const DXVA_NominalRangeMask: DXVA_NominalRange = 28672i32;
pub const DXVA_NominalRange_Unknown: DXVA_NominalRange = 0i32;
pub const DXVA_NominalRange_Normal: DXVA_NominalRange = 1i32;
pub const DXVA_NominalRange_Wide: DXVA_NominalRange = 2i32;
pub const DXVA_NominalRange_0_255: DXVA_NominalRange = 1i32;
pub const DXVA_NominalRange_16_235: DXVA_NominalRange = 2i32;
pub const DXVA_NominalRange_48_208: DXVA_NominalRange = 3i32;
#[repr(C, packed(1))]
pub struct DXVA_PictureParameters {
    pub wDecodedPictureIndex: u16,
    pub wDeblockedPictureIndex: u16,
    pub wForwardRefPictureIndex: u16,
    pub wBackwardRefPictureIndex: u16,
    pub wPicWidthInMBminus1: u16,
    pub wPicHeightInMBminus1: u16,
    pub bMacroblockWidthMinus1: u8,
    pub bMacroblockHeightMinus1: u8,
    pub bBlockWidthMinus1: u8,
    pub bBlockHeightMinus1: u8,
    pub bBPPminus1: u8,
    pub bPicStructure: u8,
    pub bSecondField: u8,
    pub bPicIntra: u8,
    pub bPicBackwardPrediction: u8,
    pub bBidirectionalAveragingMode: u8,
    pub bMVprecisionAndChromaRelation: u8,
    pub bChromaFormat: u8,
    pub bPicScanFixed: u8,
    pub bPicScanMethod: u8,
    pub bPicReadbackRequests: u8,
    pub bRcontrol: u8,
    pub bPicSpatialResid8: u8,
    pub bPicOverflowBlocks: u8,
    pub bPicExtrapolation: u8,
    pub bPicDeblocked: u8,
    pub bPicDeblockConfined: u8,
    pub bPic4MVallowed: u8,
    pub bPicOBMC: u8,
    pub bPicBinPB: u8,
    pub bMV_RPS: u8,
    pub bReservedBits: u8,
    pub wBitstreamFcodes: u16,
    pub wBitstreamPCEelements: u16,
    pub bBitstreamConcealmentNeed: u8,
    pub bBitstreamConcealmentMethod: u8,
}
impl ::core::marker::Copy for DXVA_PictureParameters {}
impl ::core::clone::Clone for DXVA_PictureParameters {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVA_ProcAmpControlBlt {
    pub Size: u32,
    pub DstRect: super::super::Foundation::RECT,
    pub SrcRect: super::super::Foundation::RECT,
    pub Alpha: f32,
    pub Brightness: f32,
    pub Contrast: f32,
    pub Hue: f32,
    pub Saturation: f32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVA_ProcAmpControlBlt {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVA_ProcAmpControlBlt {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVA_ProcAmpControlCaps {
    pub Size: u32,
    pub InputPool: u32,
    pub d3dOutputFormat: super::super::Graphics::Direct3D9::D3DFORMAT,
    pub ProcAmpControlProps: u32,
    pub VideoProcessingCaps: u32,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVA_ProcAmpControlCaps {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVA_ProcAmpControlCaps {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA_ProcAmpControlProp = i32;
pub const DXVA_ProcAmp_None: DXVA_ProcAmpControlProp = 0i32;
pub const DXVA_ProcAmp_Brightness: DXVA_ProcAmpControlProp = 1i32;
pub const DXVA_ProcAmp_Contrast: DXVA_ProcAmpControlProp = 2i32;
pub const DXVA_ProcAmp_Hue: DXVA_ProcAmpControlProp = 4i32;
pub const DXVA_ProcAmp_Saturation: DXVA_ProcAmpControlProp = 8i32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVA_ProcAmpControlQueryRange {
    pub Size: u32,
    pub ProcAmpControlProp: DXVA_ProcAmpControlProp,
    pub VideoDesc: DXVA_VideoDesc,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVA_ProcAmpControlQueryRange {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVA_ProcAmpControlQueryRange {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA_SampleFlags = i32;
pub const DXVA_SampleFlagsMask: DXVA_SampleFlags = 15i32;
pub const DXVA_SampleFlag_Palette_Changed: DXVA_SampleFlags = 1i32;
pub const DXVA_SampleFlag_SrcRect_Changed: DXVA_SampleFlags = 2i32;
pub const DXVA_SampleFlag_DstRect_Changed: DXVA_SampleFlags = 4i32;
pub const DXVA_SampleFlag_ColorData_Changed: DXVA_SampleFlags = 8i32;
pub type DXVA_SampleFormat = i32;
pub const DXVA_SampleFormatMask: DXVA_SampleFormat = 255i32;
pub const DXVA_SampleUnknown: DXVA_SampleFormat = 0i32;
pub const DXVA_SamplePreviousFrame: DXVA_SampleFormat = 1i32;
pub const DXVA_SampleProgressiveFrame: DXVA_SampleFormat = 2i32;
pub const DXVA_SampleFieldInterleavedEvenFirst: DXVA_SampleFormat = 3i32;
pub const DXVA_SampleFieldInterleavedOddFirst: DXVA_SampleFormat = 4i32;
pub const DXVA_SampleFieldSingleEven: DXVA_SampleFormat = 5i32;
pub const DXVA_SampleFieldSingleOdd: DXVA_SampleFormat = 6i32;
pub const DXVA_SampleSubStream: DXVA_SampleFormat = 7i32;
pub type DXVA_VideoChromaSubsampling = i32;
pub const DXVA_VideoChromaSubsamplingShift: DXVA_VideoChromaSubsampling = 8i32;
pub const DXVA_VideoChromaSubsamplingMask: DXVA_VideoChromaSubsampling = 3840i32;
pub const DXVA_VideoChromaSubsampling_Unknown: DXVA_VideoChromaSubsampling = 0i32;
pub const DXVA_VideoChromaSubsampling_ProgressiveChroma: DXVA_VideoChromaSubsampling = 8i32;
pub const DXVA_VideoChromaSubsampling_Horizontally_Cosited: DXVA_VideoChromaSubsampling = 4i32;
pub const DXVA_VideoChromaSubsampling_Vertically_Cosited: DXVA_VideoChromaSubsampling = 2i32;
pub const DXVA_VideoChromaSubsampling_Vertically_AlignedChromaPlanes: DXVA_VideoChromaSubsampling = 1i32;
pub const DXVA_VideoChromaSubsampling_MPEG2: DXVA_VideoChromaSubsampling = 5i32;
pub const DXVA_VideoChromaSubsampling_MPEG1: DXVA_VideoChromaSubsampling = 1i32;
pub const DXVA_VideoChromaSubsampling_DV_PAL: DXVA_VideoChromaSubsampling = 6i32;
pub const DXVA_VideoChromaSubsampling_Cosited: DXVA_VideoChromaSubsampling = 7i32;
#[repr(C)]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct DXVA_VideoDesc {
    pub Size: u32,
    pub SampleWidth: u32,
    pub SampleHeight: u32,
    pub SampleFormat: u32,
    pub d3dFormat: super::super::Graphics::Direct3D9::D3DFORMAT,
    pub InputSampleFreq: DXVA_Frequency,
    pub OutputFrameFreq: DXVA_Frequency,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for DXVA_VideoDesc {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for DXVA_VideoDesc {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA_VideoLighting = i32;
pub const DXVA_VideoLightingShift: DXVA_VideoLighting = 18i32;
pub const DXVA_VideoLightingMask: DXVA_VideoLighting = 3932160i32;
pub const DXVA_VideoLighting_Unknown: DXVA_VideoLighting = 0i32;
pub const DXVA_VideoLighting_bright: DXVA_VideoLighting = 1i32;
pub const DXVA_VideoLighting_office: DXVA_VideoLighting = 2i32;
pub const DXVA_VideoLighting_dim: DXVA_VideoLighting = 3i32;
pub const DXVA_VideoLighting_dark: DXVA_VideoLighting = 4i32;
pub type DXVA_VideoPrimaries = i32;
pub const DXVA_VideoPrimariesShift: DXVA_VideoPrimaries = 22i32;
pub const DXVA_VideoPrimariesMask: DXVA_VideoPrimaries = 130023424i32;
pub const DXVA_VideoPrimaries_Unknown: DXVA_VideoPrimaries = 0i32;
pub const DXVA_VideoPrimaries_reserved: DXVA_VideoPrimaries = 1i32;
pub const DXVA_VideoPrimaries_BT709: DXVA_VideoPrimaries = 2i32;
pub const DXVA_VideoPrimaries_BT470_2_SysM: DXVA_VideoPrimaries = 3i32;
pub const DXVA_VideoPrimaries_BT470_2_SysBG: DXVA_VideoPrimaries = 4i32;
pub const DXVA_VideoPrimaries_SMPTE170M: DXVA_VideoPrimaries = 5i32;
pub const DXVA_VideoPrimaries_SMPTE240M: DXVA_VideoPrimaries = 6i32;
pub const DXVA_VideoPrimaries_EBU3213: DXVA_VideoPrimaries = 7i32;
pub const DXVA_VideoPrimaries_SMPTE_C: DXVA_VideoPrimaries = 8i32;
pub type DXVA_VideoProcessCaps = i32;
pub const DXVA_VideoProcess_None: DXVA_VideoProcessCaps = 0i32;
pub const DXVA_VideoProcess_YUV2RGB: DXVA_VideoProcessCaps = 1i32;
pub const DXVA_VideoProcess_StretchX: DXVA_VideoProcessCaps = 2i32;
pub const DXVA_VideoProcess_StretchY: DXVA_VideoProcessCaps = 4i32;
pub const DXVA_VideoProcess_AlphaBlend: DXVA_VideoProcessCaps = 8i32;
pub const DXVA_VideoProcess_SubRects: DXVA_VideoProcessCaps = 16i32;
pub const DXVA_VideoProcess_SubStreams: DXVA_VideoProcessCaps = 32i32;
pub const DXVA_VideoProcess_SubStreamsExtended: DXVA_VideoProcessCaps = 64i32;
pub const DXVA_VideoProcess_YUV2RGBExtended: DXVA_VideoProcessCaps = 128i32;
pub const DXVA_VideoProcess_AlphaBlendExtended: DXVA_VideoProcessCaps = 256i32;
#[repr(C)]
pub struct DXVA_VideoPropertyRange {
    pub MinValue: f32,
    pub MaxValue: f32,
    pub DefaultValue: f32,
    pub StepSize: f32,
}
impl ::core::marker::Copy for DXVA_VideoPropertyRange {}
impl ::core::clone::Clone for DXVA_VideoPropertyRange {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct DXVA_VideoSample {
    pub rtStart: i64,
    pub rtEnd: i64,
    pub SampleFormat: DXVA_SampleFormat,
    pub lpDDSSrcSurface: *mut ::core::ffi::c_void,
}
impl ::core::marker::Copy for DXVA_VideoSample {}
impl ::core::clone::Clone for DXVA_VideoSample {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVA_VideoSample2 {
    pub Size: u32,
    pub Reserved: u32,
    pub rtStart: i64,
    pub rtEnd: i64,
    pub SampleFormat: u32,
    pub SampleFlags: u32,
    pub lpDDSSrcSurface: *mut ::core::ffi::c_void,
    pub rcSrc: super::super::Foundation::RECT,
    pub rcDst: super::super::Foundation::RECT,
    pub Palette: [DXVA_AYUVsample2; 16],
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVA_VideoSample2 {}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVA_VideoSample2 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(any(target_arch = "x86",))]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVA_VideoSample2 {
    pub rtStart: i64,
    pub rtEnd: i64,
    pub SampleFormat: u32,
    pub SampleFlags: u32,
    pub lpDDSSrcSurface: *mut ::core::ffi::c_void,
    pub rcSrc: super::super::Foundation::RECT,
    pub rcDst: super::super::Foundation::RECT,
    pub Palette: [DXVA_AYUVsample2; 16],
}
#[cfg(any(target_arch = "x86",))]
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVA_VideoSample2 {}
#[cfg(any(target_arch = "x86",))]
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVA_VideoSample2 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
#[cfg(feature = "Win32_Foundation")]
pub struct DXVA_VideoSample32 {
    pub rtStart: i64,
    pub rtEnd: i64,
    pub SampleFormat: u32,
    pub SampleFlags: u32,
    pub lpDDSSrcSurface: u32,
    pub rcSrc: super::super::Foundation::RECT,
    pub rcDst: super::super::Foundation::RECT,
    pub Palette: [DXVA_AYUVsample2; 16],
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for DXVA_VideoSample32 {}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64",))]
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for DXVA_VideoSample32 {
    fn clone(&self) -> Self {
        *self
    }
}
pub type DXVA_VideoTransferFunction = i32;
pub const DXVA_VideoTransFuncShift: DXVA_VideoTransferFunction = 27i32;
pub const DXVA_VideoTransFuncMask: DXVA_VideoTransferFunction = -134217728i32;
pub const DXVA_VideoTransFunc_Unknown: DXVA_VideoTransferFunction = 0i32;
pub const DXVA_VideoTransFunc_10: DXVA_VideoTransferFunction = 1i32;
pub const DXVA_VideoTransFunc_18: DXVA_VideoTransferFunction = 2i32;
pub const DXVA_VideoTransFunc_20: DXVA_VideoTransferFunction = 3i32;
pub const DXVA_VideoTransFunc_22: DXVA_VideoTransferFunction = 4i32;
pub const DXVA_VideoTransFunc_22_709: DXVA_VideoTransferFunction = 5i32;
pub const DXVA_VideoTransFunc_22_240M: DXVA_VideoTransferFunction = 6i32;
pub const DXVA_VideoTransFunc_22_8bit_sRGB: DXVA_VideoTransferFunction = 7i32;
pub const DXVA_VideoTransFunc_28: DXVA_VideoTransferFunction = 8i32;
pub type DXVA_VideoTransferMatrix = i32;
pub const DXVA_VideoTransferMatrixShift: DXVA_VideoTransferMatrix = 15i32;
pub const DXVA_VideoTransferMatrixMask: DXVA_VideoTransferMatrix = 229376i32;
pub const DXVA_VideoTransferMatrix_Unknown: DXVA_VideoTransferMatrix = 0i32;
pub const DXVA_VideoTransferMatrix_BT709: DXVA_VideoTransferMatrix = 1i32;
pub const DXVA_VideoTransferMatrix_BT601: DXVA_VideoTransferMatrix = 2i32;
pub const DXVA_VideoTransferMatrix_SMPTE240M: DXVA_VideoTransferMatrix = 3i32;
pub const DXVAp_DeinterlaceBobDevice: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 861578094,
    data2: 30852,
    data3: 17316,
    data4: [156, 145, 127, 135, 250, 243, 227, 126],
};
pub const DXVAp_DeinterlaceContainerDevice: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 243649427,
    data2: 12358,
    data3: 20464,
    data4: [174, 204, 213, 140, 181, 240, 53, 253],
};
pub const DXVAp_ModeMPEG2_A: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487626, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVAp_ModeMPEG2_C: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487628, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub const DXVAp_NoEncrypt: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 461487824, data2: 41159, data3: 4563, data4: [185, 132, 0, 192, 79, 46, 115, 197] };
pub type DeviceStreamState = i32;
pub const DeviceStreamState_Stop: DeviceStreamState = 0i32;
pub const DeviceStreamState_Pause: DeviceStreamState = 1i32;
pub const DeviceStreamState_Run: DeviceStreamState = 2i32;
pub const DeviceStreamState_Disabled: DeviceStreamState = 3i32;
#[repr(C)]
pub struct DigitalWindowSetting {
    pub OriginX: f64,
    pub OriginY: f64,
    pub WindowSize: f64,
}
impl ::core::marker::Copy for DigitalWindowSetting {}
impl ::core::clone::Clone for DigitalWindowSetting {
    fn clone(&self) -> Self {
        *self
    }
}
pub type EAllocationType = i32;
pub const eAllocationTypeDynamic: EAllocationType = 0i32;
pub const eAllocationTypeRT: EAllocationType = 1i32;
pub const eAllocationTypePageable: EAllocationType = 2i32;
pub const eAllocationTypeIgnore: EAllocationType = 3i32;
pub type EVRFilterConfigPrefs = i32;
pub const EVRFilterConfigPrefs_EnableQoS: EVRFilterConfigPrefs = 1i32;
pub const EVRFilterConfigPrefs_Mask: EVRFilterConfigPrefs = 1i32;
pub const E_TOCPARSER_INVALIDASFFILE: ::windows_sys::core::HRESULT = -1728053247i32;
pub const E_TOCPARSER_INVALIDRIFFFILE: ::windows_sys::core::HRESULT = -1728053246i32;
pub const FACILITY_MF: u32 = 13u32;
pub const FACILITY_MF_WIN32: u32 = 7u32;
pub type FILE_ACCESSMODE = i32;
pub const ACCESSMODE_READ: FILE_ACCESSMODE = 1i32;
pub const ACCESSMODE_WRITE: FILE_ACCESSMODE = 2i32;
pub const ACCESSMODE_READWRITE: FILE_ACCESSMODE = 3i32;
pub const ACCESSMODE_WRITE_EXCLUSIVE: FILE_ACCESSMODE = 4i32;
pub type FILE_OPENMODE = i32;
pub const OPENMODE_FAIL_IF_NOT_EXIST: FILE_OPENMODE = 0i32;
pub const OPENMODE_FAIL_IF_EXIST: FILE_OPENMODE = 1i32;
pub const OPENMODE_RESET_IF_EXIST: FILE_OPENMODE = 2i32;
pub const OPENMODE_APPEND_IF_EXIST: FILE_OPENMODE = 3i32;
pub const OPENMODE_DELETE_IF_EXIST: FILE_OPENMODE = 4i32;
pub const FORMAT_MFVideoFormat: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2933173037,
    data2: 29478,
    data3: 17355,
    data4: [148, 100, 200, 121, 202, 185, 196, 61],
};
pub const GUID_NativeDeviceService: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4017218876,
    data2: 21236,
    data3: 17349,
    data4: [184, 106, 173, 108, 178, 22, 166, 30],
};
pub const GUID_PlayToService: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4138270621, data2: 40468, data3: 16841, data4: [191, 15, 18, 10, 43, 60, 225, 32] };
pub type IAdvancedMediaCapture = *mut ::core::ffi::c_void;
pub type IAdvancedMediaCaptureInitializationSettings = *mut ::core::ffi::c_void;
pub type IAdvancedMediaCaptureSettings = *mut ::core::ffi::c_void;
pub type IAudioSourceProvider = *mut ::core::ffi::c_void;
pub type IClusterDetector = *mut ::core::ffi::c_void;
pub type ICodecAPI = *mut ::core::ffi::c_void;
pub type ID3D12VideoDecodeCommandList = *mut ::core::ffi::c_void;
pub type ID3D12VideoDecodeCommandList1 = *mut ::core::ffi::c_void;
pub type ID3D12VideoDecodeCommandList2 = *mut ::core::ffi::c_void;
pub type ID3D12VideoDecoder = *mut ::core::ffi::c_void;
pub type ID3D12VideoDecoder1 = *mut ::core::ffi::c_void;
pub type ID3D12VideoDecoderHeap = *mut ::core::ffi::c_void;
pub type ID3D12VideoDecoderHeap1 = *mut ::core::ffi::c_void;
pub type ID3D12VideoDevice = *mut ::core::ffi::c_void;
pub type ID3D12VideoDevice1 = *mut ::core::ffi::c_void;
pub type ID3D12VideoDevice2 = *mut ::core::ffi::c_void;
pub type ID3D12VideoDevice3 = *mut ::core::ffi::c_void;
pub type ID3D12VideoEncodeCommandList = *mut ::core::ffi::c_void;
pub type ID3D12VideoEncodeCommandList1 = *mut ::core::ffi::c_void;
pub type ID3D12VideoEncodeCommandList2 = *mut ::core::ffi::c_void;
pub type ID3D12VideoEncoder = *mut ::core::ffi::c_void;
pub type ID3D12VideoEncoderHeap = *mut ::core::ffi::c_void;
pub type ID3D12VideoExtensionCommand = *mut ::core::ffi::c_void;
pub type ID3D12VideoMotionEstimator = *mut ::core::ffi::c_void;
pub type ID3D12VideoMotionVectorHeap = *mut ::core::ffi::c_void;
pub type ID3D12VideoProcessCommandList = *mut ::core::ffi::c_void;
pub type ID3D12VideoProcessCommandList1 = *mut ::core::ffi::c_void;
pub type ID3D12VideoProcessCommandList2 = *mut ::core::ffi::c_void;
pub type ID3D12VideoProcessor = *mut ::core::ffi::c_void;
pub type ID3D12VideoProcessor1 = *mut ::core::ffi::c_void;
pub type IDXVAHD_Device = *mut ::core::ffi::c_void;
pub type IDXVAHD_VideoProcessor = *mut ::core::ffi::c_void;
pub type IDirect3D9ExOverlayExtension = *mut ::core::ffi::c_void;
pub type IDirect3DAuthenticatedChannel9 = *mut ::core::ffi::c_void;
pub type IDirect3DCryptoSession9 = *mut ::core::ffi::c_void;
pub type IDirect3DDevice9Video = *mut ::core::ffi::c_void;
pub type IDirect3DDeviceManager9 = *mut ::core::ffi::c_void;
pub type IDirectXVideoAccelerationService = *mut ::core::ffi::c_void;
pub type IDirectXVideoDecoder = *mut ::core::ffi::c_void;
pub type IDirectXVideoDecoderService = *mut ::core::ffi::c_void;
pub type IDirectXVideoMemoryConfiguration = *mut ::core::ffi::c_void;
pub type IDirectXVideoProcessor = *mut ::core::ffi::c_void;
pub type IDirectXVideoProcessorService = *mut ::core::ffi::c_void;
pub type IEVRFilterConfig = *mut ::core::ffi::c_void;
pub type IEVRFilterConfigEx = *mut ::core::ffi::c_void;
pub type IEVRTrustedVideoPlugin = *mut ::core::ffi::c_void;
pub type IEVRVideoStreamControl = *mut ::core::ffi::c_void;
pub type IFileClient = *mut ::core::ffi::c_void;
pub type IFileIo = *mut ::core::ffi::c_void;
pub type IMF2DBuffer = *mut ::core::ffi::c_void;
pub type IMF2DBuffer2 = *mut ::core::ffi::c_void;
pub type IMFASFContentInfo = *mut ::core::ffi::c_void;
pub type IMFASFIndexer = *mut ::core::ffi::c_void;
pub type IMFASFMultiplexer = *mut ::core::ffi::c_void;
pub type IMFASFMutualExclusion = *mut ::core::ffi::c_void;
pub type IMFASFProfile = *mut ::core::ffi::c_void;
pub type IMFASFSplitter = *mut ::core::ffi::c_void;
pub type IMFASFStreamConfig = *mut ::core::ffi::c_void;
pub type IMFASFStreamPrioritization = *mut ::core::ffi::c_void;
pub type IMFASFStreamSelector = *mut ::core::ffi::c_void;
pub type IMFActivate = *mut ::core::ffi::c_void;
pub type IMFAsyncCallback = *mut ::core::ffi::c_void;
pub type IMFAsyncCallbackLogging = *mut ::core::ffi::c_void;
pub type IMFAsyncResult = *mut ::core::ffi::c_void;
pub type IMFAttributes = *mut ::core::ffi::c_void;
pub type IMFAudioMediaType = *mut ::core::ffi::c_void;
pub type IMFAudioPolicy = *mut ::core::ffi::c_void;
pub type IMFAudioStreamVolume = *mut ::core::ffi::c_void;
pub type IMFBufferListNotify = *mut ::core::ffi::c_void;
pub type IMFByteStream = *mut ::core::ffi::c_void;
pub type IMFByteStreamBuffering = *mut ::core::ffi::c_void;
pub type IMFByteStreamCacheControl = *mut ::core::ffi::c_void;
pub type IMFByteStreamCacheControl2 = *mut ::core::ffi::c_void;
pub type IMFByteStreamHandler = *mut ::core::ffi::c_void;
pub type IMFByteStreamProxyClassFactory = *mut ::core::ffi::c_void;
pub type IMFByteStreamTimeSeek = *mut ::core::ffi::c_void;
pub type IMFCameraOcclusionStateMonitor = *mut ::core::ffi::c_void;
pub type IMFCameraOcclusionStateReport = *mut ::core::ffi::c_void;
pub type IMFCameraOcclusionStateReportCallback = *mut ::core::ffi::c_void;
pub type IMFCameraSyncObject = *mut ::core::ffi::c_void;
pub type IMFCaptureEngine = *mut ::core::ffi::c_void;
pub type IMFCaptureEngineClassFactory = *mut ::core::ffi::c_void;
pub type IMFCaptureEngineOnEventCallback = *mut ::core::ffi::c_void;
pub type IMFCaptureEngineOnSampleCallback = *mut ::core::ffi::c_void;
pub type IMFCaptureEngineOnSampleCallback2 = *mut ::core::ffi::c_void;
pub type IMFCapturePhotoConfirmation = *mut ::core::ffi::c_void;
pub type IMFCapturePhotoSink = *mut ::core::ffi::c_void;
pub type IMFCapturePreviewSink = *mut ::core::ffi::c_void;
pub type IMFCaptureRecordSink = *mut ::core::ffi::c_void;
pub type IMFCaptureSink = *mut ::core::ffi::c_void;
pub type IMFCaptureSink2 = *mut ::core::ffi::c_void;
pub type IMFCaptureSource = *mut ::core::ffi::c_void;
pub type IMFCdmSuspendNotify = *mut ::core::ffi::c_void;
pub type IMFClock = *mut ::core::ffi::c_void;
pub type IMFClockConsumer = *mut ::core::ffi::c_void;
pub type IMFClockStateSink = *mut ::core::ffi::c_void;
pub type IMFCollection = *mut ::core::ffi::c_void;
pub type IMFContentDecryptionModule = *mut ::core::ffi::c_void;
pub type IMFContentDecryptionModuleAccess = *mut ::core::ffi::c_void;
pub type IMFContentDecryptionModuleFactory = *mut ::core::ffi::c_void;
pub type IMFContentDecryptionModuleSession = *mut ::core::ffi::c_void;
pub type IMFContentDecryptionModuleSessionCallbacks = *mut ::core::ffi::c_void;
pub type IMFContentDecryptorContext = *mut ::core::ffi::c_void;
pub type IMFContentEnabler = *mut ::core::ffi::c_void;
pub type IMFContentProtectionDevice = *mut ::core::ffi::c_void;
pub type IMFContentProtectionManager = *mut ::core::ffi::c_void;
pub type IMFD3D12SynchronizationObject = *mut ::core::ffi::c_void;
pub type IMFD3D12SynchronizationObjectCommands = *mut ::core::ffi::c_void;
pub type IMFDLNASinkInit = *mut ::core::ffi::c_void;
pub type IMFDRMNetHelper = *mut ::core::ffi::c_void;
pub type IMFDXGIBuffer = *mut ::core::ffi::c_void;
pub type IMFDXGIDeviceManager = *mut ::core::ffi::c_void;
pub type IMFDXGIDeviceManagerSource = *mut ::core::ffi::c_void;
pub type IMFDesiredSample = *mut ::core::ffi::c_void;
pub type IMFExtendedCameraControl = *mut ::core::ffi::c_void;
pub type IMFExtendedCameraController = *mut ::core::ffi::c_void;
pub type IMFExtendedCameraIntrinsicModel = *mut ::core::ffi::c_void;
pub type IMFExtendedCameraIntrinsics = *mut ::core::ffi::c_void;
pub type IMFExtendedCameraIntrinsicsDistortionModel6KT = *mut ::core::ffi::c_void;
pub type IMFExtendedCameraIntrinsicsDistortionModelArcTan = *mut ::core::ffi::c_void;
pub type IMFExtendedDRMTypeSupport = *mut ::core::ffi::c_void;
pub type IMFFieldOfUseMFTUnlock = *mut ::core::ffi::c_void;
pub type IMFFinalizableMediaSink = *mut ::core::ffi::c_void;
pub type IMFGetService = *mut ::core::ffi::c_void;
pub type IMFHDCPStatus = *mut ::core::ffi::c_void;
pub type IMFHttpDownloadRequest = *mut ::core::ffi::c_void;
pub type IMFHttpDownloadSession = *mut ::core::ffi::c_void;
pub type IMFHttpDownloadSessionProvider = *mut ::core::ffi::c_void;
pub type IMFImageSharingEngine = *mut ::core::ffi::c_void;
pub type IMFImageSharingEngineClassFactory = *mut ::core::ffi::c_void;
pub type IMFInputTrustAuthority = *mut ::core::ffi::c_void;
pub type IMFLocalMFTRegistration = *mut ::core::ffi::c_void;
pub type IMFMediaBuffer = *mut ::core::ffi::c_void;
pub type IMFMediaEngine = *mut ::core::ffi::c_void;
pub type IMFMediaEngineAudioEndpointId = *mut ::core::ffi::c_void;
pub type IMFMediaEngineClassFactory = *mut ::core::ffi::c_void;
pub type IMFMediaEngineClassFactory2 = *mut ::core::ffi::c_void;
pub type IMFMediaEngineClassFactory3 = *mut ::core::ffi::c_void;
pub type IMFMediaEngineClassFactory4 = *mut ::core::ffi::c_void;
pub type IMFMediaEngineClassFactoryEx = *mut ::core::ffi::c_void;
pub type IMFMediaEngineEME = *mut ::core::ffi::c_void;
pub type IMFMediaEngineEMENotify = *mut ::core::ffi::c_void;
pub type IMFMediaEngineEx = *mut ::core::ffi::c_void;
pub type IMFMediaEngineExtension = *mut ::core::ffi::c_void;
pub type IMFMediaEngineNeedKeyNotify = *mut ::core::ffi::c_void;
pub type IMFMediaEngineNotify = *mut ::core::ffi::c_void;
pub type IMFMediaEngineOPMInfo = *mut ::core::ffi::c_void;
pub type IMFMediaEngineProtectedContent = *mut ::core::ffi::c_void;
pub type IMFMediaEngineSrcElements = *mut ::core::ffi::c_void;
pub type IMFMediaEngineSrcElementsEx = *mut ::core::ffi::c_void;
pub type IMFMediaEngineSupportsSourceTransfer = *mut ::core::ffi::c_void;
pub type IMFMediaEngineTransferSource = *mut ::core::ffi::c_void;
pub type IMFMediaEngineWebSupport = *mut ::core::ffi::c_void;
pub type IMFMediaError = *mut ::core::ffi::c_void;
pub type IMFMediaEvent = *mut ::core::ffi::c_void;
pub type IMFMediaEventGenerator = *mut ::core::ffi::c_void;
pub type IMFMediaEventQueue = *mut ::core::ffi::c_void;
pub type IMFMediaKeySession = *mut ::core::ffi::c_void;
pub type IMFMediaKeySession2 = *mut ::core::ffi::c_void;
pub type IMFMediaKeySessionNotify = *mut ::core::ffi::c_void;
pub type IMFMediaKeySessionNotify2 = *mut ::core::ffi::c_void;
pub type IMFMediaKeySystemAccess = *mut ::core::ffi::c_void;
pub type IMFMediaKeys = *mut ::core::ffi::c_void;
pub type IMFMediaKeys2 = *mut ::core::ffi::c_void;
pub type IMFMediaSession = *mut ::core::ffi::c_void;
pub type IMFMediaSharingEngine = *mut ::core::ffi::c_void;
pub type IMFMediaSharingEngineClassFactory = *mut ::core::ffi::c_void;
pub type IMFMediaSink = *mut ::core::ffi::c_void;
pub type IMFMediaSinkPreroll = *mut ::core::ffi::c_void;
pub type IMFMediaSource = *mut ::core::ffi::c_void;
pub type IMFMediaSource2 = *mut ::core::ffi::c_void;
pub type IMFMediaSourceEx = *mut ::core::ffi::c_void;
pub type IMFMediaSourceExtension = *mut ::core::ffi::c_void;
pub type IMFMediaSourceExtensionLiveSeekableRange = *mut ::core::ffi::c_void;
pub type IMFMediaSourceExtensionNotify = *mut ::core::ffi::c_void;
pub type IMFMediaSourcePresentationProvider = *mut ::core::ffi::c_void;
pub type IMFMediaSourceTopologyProvider = *mut ::core::ffi::c_void;
pub type IMFMediaStream = *mut ::core::ffi::c_void;
pub type IMFMediaStream2 = *mut ::core::ffi::c_void;
pub type IMFMediaStreamSourceSampleRequest = *mut ::core::ffi::c_void;
pub type IMFMediaTimeRange = *mut ::core::ffi::c_void;
pub type IMFMediaType = *mut ::core::ffi::c_void;
pub type IMFMediaTypeHandler = *mut ::core::ffi::c_void;
pub type IMFMetadata = *mut ::core::ffi::c_void;
pub type IMFMetadataProvider = *mut ::core::ffi::c_void;
pub type IMFMuxStreamAttributesManager = *mut ::core::ffi::c_void;
pub type IMFMuxStreamMediaTypeManager = *mut ::core::ffi::c_void;
pub type IMFMuxStreamSampleManager = *mut ::core::ffi::c_void;
pub type IMFNetCredential = *mut ::core::ffi::c_void;
pub type IMFNetCredentialCache = *mut ::core::ffi::c_void;
pub type IMFNetCredentialManager = *mut ::core::ffi::c_void;
pub type IMFNetCrossOriginSupport = *mut ::core::ffi::c_void;
pub type IMFNetProxyLocator = *mut ::core::ffi::c_void;
pub type IMFNetProxyLocatorFactory = *mut ::core::ffi::c_void;
pub type IMFNetResourceFilter = *mut ::core::ffi::c_void;
pub type IMFNetSchemeHandlerConfig = *mut ::core::ffi::c_void;
pub type IMFObjectReferenceStream = *mut ::core::ffi::c_void;
pub type IMFOutputPolicy = *mut ::core::ffi::c_void;
pub type IMFOutputSchema = *mut ::core::ffi::c_void;
pub type IMFOutputTrustAuthority = *mut ::core::ffi::c_void;
pub type IMFPMPClient = *mut ::core::ffi::c_void;
pub type IMFPMPClientApp = *mut ::core::ffi::c_void;
pub type IMFPMPHost = *mut ::core::ffi::c_void;
pub type IMFPMPHostApp = *mut ::core::ffi::c_void;
pub type IMFPMPServer = *mut ::core::ffi::c_void;
pub type IMFPMediaItem = *mut ::core::ffi::c_void;
pub type IMFPMediaPlayer = *mut ::core::ffi::c_void;
pub type IMFPMediaPlayerCallback = *mut ::core::ffi::c_void;
pub type IMFPluginControl = *mut ::core::ffi::c_void;
pub type IMFPluginControl2 = *mut ::core::ffi::c_void;
pub type IMFPresentationClock = *mut ::core::ffi::c_void;
pub type IMFPresentationDescriptor = *mut ::core::ffi::c_void;
pub type IMFPresentationTimeSource = *mut ::core::ffi::c_void;
pub type IMFProtectedEnvironmentAccess = *mut ::core::ffi::c_void;
pub type IMFQualityAdvise = *mut ::core::ffi::c_void;
pub type IMFQualityAdvise2 = *mut ::core::ffi::c_void;
pub type IMFQualityAdviseLimits = *mut ::core::ffi::c_void;
pub type IMFQualityManager = *mut ::core::ffi::c_void;
pub type IMFRateControl = *mut ::core::ffi::c_void;
pub type IMFRateSupport = *mut ::core::ffi::c_void;
pub type IMFReadWriteClassFactory = *mut ::core::ffi::c_void;
pub type IMFRealTimeClient = *mut ::core::ffi::c_void;
pub type IMFRealTimeClientEx = *mut ::core::ffi::c_void;
pub type IMFRelativePanelReport = *mut ::core::ffi::c_void;
pub type IMFRelativePanelWatcher = *mut ::core::ffi::c_void;
pub type IMFRemoteAsyncCallback = *mut ::core::ffi::c_void;
pub type IMFRemoteDesktopPlugin = *mut ::core::ffi::c_void;
pub type IMFRemoteProxy = *mut ::core::ffi::c_void;
pub type IMFSAMIStyle = *mut ::core::ffi::c_void;
pub type IMFSSLCertificateManager = *mut ::core::ffi::c_void;
pub type IMFSample = *mut ::core::ffi::c_void;
pub type IMFSampleAllocatorControl = *mut ::core::ffi::c_void;
pub type IMFSampleGrabberSinkCallback = *mut ::core::ffi::c_void;
pub type IMFSampleGrabberSinkCallback2 = *mut ::core::ffi::c_void;
pub type IMFSampleOutputStream = *mut ::core::ffi::c_void;
pub type IMFSampleProtection = *mut ::core::ffi::c_void;
pub type IMFSaveJob = *mut ::core::ffi::c_void;
pub type IMFSchemeHandler = *mut ::core::ffi::c_void;
pub type IMFSecureBuffer = *mut ::core::ffi::c_void;
pub type IMFSecureChannel = *mut ::core::ffi::c_void;
pub type IMFSeekInfo = *mut ::core::ffi::c_void;
pub type IMFSensorActivitiesReport = *mut ::core::ffi::c_void;
pub type IMFSensorActivitiesReportCallback = *mut ::core::ffi::c_void;
pub type IMFSensorActivityMonitor = *mut ::core::ffi::c_void;
pub type IMFSensorActivityReport = *mut ::core::ffi::c_void;
pub type IMFSensorDevice = *mut ::core::ffi::c_void;
pub type IMFSensorGroup = *mut ::core::ffi::c_void;
pub type IMFSensorProcessActivity = *mut ::core::ffi::c_void;
pub type IMFSensorProfile = *mut ::core::ffi::c_void;
pub type IMFSensorProfileCollection = *mut ::core::ffi::c_void;
pub type IMFSensorStream = *mut ::core::ffi::c_void;
pub type IMFSensorTransformFactory = *mut ::core::ffi::c_void;
pub type IMFSequencerSource = *mut ::core::ffi::c_void;
pub type IMFSharingEngineClassFactory = *mut ::core::ffi::c_void;
pub type IMFShutdown = *mut ::core::ffi::c_void;
pub type IMFSignedLibrary = *mut ::core::ffi::c_void;
pub type IMFSimpleAudioVolume = *mut ::core::ffi::c_void;
pub type IMFSinkWriter = *mut ::core::ffi::c_void;
pub type IMFSinkWriterCallback = *mut ::core::ffi::c_void;
pub type IMFSinkWriterCallback2 = *mut ::core::ffi::c_void;
pub type IMFSinkWriterEncoderConfig = *mut ::core::ffi::c_void;
pub type IMFSinkWriterEx = *mut ::core::ffi::c_void;
pub type IMFSourceBuffer = *mut ::core::ffi::c_void;
pub type IMFSourceBufferAppendMode = *mut ::core::ffi::c_void;
pub type IMFSourceBufferList = *mut ::core::ffi::c_void;
pub type IMFSourceBufferNotify = *mut ::core::ffi::c_void;
pub type IMFSourceOpenMonitor = *mut ::core::ffi::c_void;
pub type IMFSourceReader = *mut ::core::ffi::c_void;
pub type IMFSourceReaderCallback = *mut ::core::ffi::c_void;
pub type IMFSourceReaderCallback2 = *mut ::core::ffi::c_void;
pub type IMFSourceReaderEx = *mut ::core::ffi::c_void;
pub type IMFSourceResolver = *mut ::core::ffi::c_void;
pub type IMFSpatialAudioObjectBuffer = *mut ::core::ffi::c_void;
pub type IMFSpatialAudioSample = *mut ::core::ffi::c_void;
pub type IMFStreamDescriptor = *mut ::core::ffi::c_void;
pub type IMFStreamSink = *mut ::core::ffi::c_void;
pub type IMFStreamingSinkConfig = *mut ::core::ffi::c_void;
pub type IMFSystemId = *mut ::core::ffi::c_void;
pub type IMFTimecodeTranslate = *mut ::core::ffi::c_void;
pub type IMFTimedText = *mut ::core::ffi::c_void;
pub type IMFTimedTextBinary = *mut ::core::ffi::c_void;
pub type IMFTimedTextBouten = *mut ::core::ffi::c_void;
pub type IMFTimedTextCue = *mut ::core::ffi::c_void;
pub type IMFTimedTextCueList = *mut ::core::ffi::c_void;
pub type IMFTimedTextFormattedText = *mut ::core::ffi::c_void;
pub type IMFTimedTextNotify = *mut ::core::ffi::c_void;
pub type IMFTimedTextRegion = *mut ::core::ffi::c_void;
pub type IMFTimedTextRuby = *mut ::core::ffi::c_void;
pub type IMFTimedTextStyle = *mut ::core::ffi::c_void;
pub type IMFTimedTextStyle2 = *mut ::core::ffi::c_void;
pub type IMFTimedTextTrack = *mut ::core::ffi::c_void;
pub type IMFTimedTextTrackList = *mut ::core::ffi::c_void;
pub type IMFTimer = *mut ::core::ffi::c_void;
pub type IMFTopoLoader = *mut ::core::ffi::c_void;
pub type IMFTopology = *mut ::core::ffi::c_void;
pub type IMFTopologyNode = *mut ::core::ffi::c_void;
pub type IMFTopologyNodeAttributeEditor = *mut ::core::ffi::c_void;
pub type IMFTopologyServiceLookup = *mut ::core::ffi::c_void;
pub type IMFTopologyServiceLookupClient = *mut ::core::ffi::c_void;
pub type IMFTrackedSample = *mut ::core::ffi::c_void;
pub type IMFTranscodeProfile = *mut ::core::ffi::c_void;
pub type IMFTranscodeSinkInfoProvider = *mut ::core::ffi::c_void;
pub type IMFTransform = *mut ::core::ffi::c_void;
pub type IMFTrustedInput = *mut ::core::ffi::c_void;
pub type IMFTrustedOutput = *mut ::core::ffi::c_void;
pub type IMFVideoCaptureSampleAllocator = *mut ::core::ffi::c_void;
pub type IMFVideoDeviceID = *mut ::core::ffi::c_void;
pub type IMFVideoDisplayControl = *mut ::core::ffi::c_void;
pub type IMFVideoMediaType = *mut ::core::ffi::c_void;
pub type IMFVideoMixerBitmap = *mut ::core::ffi::c_void;
pub type IMFVideoMixerControl = *mut ::core::ffi::c_void;
pub type IMFVideoMixerControl2 = *mut ::core::ffi::c_void;
pub type IMFVideoPositionMapper = *mut ::core::ffi::c_void;
pub type IMFVideoPresenter = *mut ::core::ffi::c_void;
pub type IMFVideoProcessor = *mut ::core::ffi::c_void;
pub type IMFVideoProcessorControl = *mut ::core::ffi::c_void;
pub type IMFVideoProcessorControl2 = *mut ::core::ffi::c_void;
pub type IMFVideoProcessorControl3 = *mut ::core::ffi::c_void;
pub type IMFVideoRenderer = *mut ::core::ffi::c_void;
pub type IMFVideoRendererEffectControl = *mut ::core::ffi::c_void;
pub type IMFVideoSampleAllocator = *mut ::core::ffi::c_void;
pub type IMFVideoSampleAllocatorCallback = *mut ::core::ffi::c_void;
pub type IMFVideoSampleAllocatorEx = *mut ::core::ffi::c_void;
pub type IMFVideoSampleAllocatorNotify = *mut ::core::ffi::c_void;
pub type IMFVideoSampleAllocatorNotifyEx = *mut ::core::ffi::c_void;
pub type IMFVirtualCamera = *mut ::core::ffi::c_void;
pub type IMFWorkQueueServices = *mut ::core::ffi::c_void;
pub type IMFWorkQueueServicesEx = *mut ::core::ffi::c_void;
pub type IOPMVideoOutput = *mut ::core::ffi::c_void;
pub type IPlayToControl = *mut ::core::ffi::c_void;
pub type IPlayToControlWithCapabilities = *mut ::core::ffi::c_void;
pub type IPlayToSourceClassFactory = *mut ::core::ffi::c_void;
pub type IToc = *mut ::core::ffi::c_void;
pub type ITocCollection = *mut ::core::ffi::c_void;
pub type ITocEntry = *mut ::core::ffi::c_void;
pub type ITocEntryList = *mut ::core::ffi::c_void;
pub type ITocParser = *mut ::core::ffi::c_void;
pub type IValidateBinding = *mut ::core::ffi::c_void;
pub type IWMCodecLeakyBucket = *mut ::core::ffi::c_void;
pub type IWMCodecOutputTimestamp = *mut ::core::ffi::c_void;
pub type IWMCodecPrivateData = *mut ::core::ffi::c_void;
pub type IWMCodecProps = *mut ::core::ffi::c_void;
pub type IWMCodecStrings = *mut ::core::ffi::c_void;
pub type IWMColorConvProps = *mut ::core::ffi::c_void;
pub type IWMColorLegalizerProps = *mut ::core::ffi::c_void;
pub type IWMFrameInterpProps = *mut ::core::ffi::c_void;
pub type IWMInterlaceProps = *mut ::core::ffi::c_void;
pub type IWMResamplerProps = *mut ::core::ffi::c_void;
pub type IWMResizerProps = *mut ::core::ffi::c_void;
pub type IWMSampleExtensionSupport = *mut ::core::ffi::c_void;
pub type IWMValidate = *mut ::core::ffi::c_void;
pub type IWMVideoDecoderHurryup = *mut ::core::ffi::c_void;
pub type IWMVideoDecoderReconBuffer = *mut ::core::ffi::c_void;
pub type IWMVideoForceKeyFrame = *mut ::core::ffi::c_void;
pub type KSMETHOD_OPMVIDEOOUTPUT = i32;
pub const KSMETHOD_OPMVIDEOOUTPUT_STARTINITIALIZATION: KSMETHOD_OPMVIDEOOUTPUT = 0i32;
pub const KSMETHOD_OPMVIDEOOUTPUT_FINISHINITIALIZATION: KSMETHOD_OPMVIDEOOUTPUT = 1i32;
pub const KSMETHOD_OPMVIDEOOUTPUT_GETINFORMATION: KSMETHOD_OPMVIDEOOUTPUT = 2i32;
pub const KSPROPSETID_OPMVideoOutput: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 116659387,
    data2: 62522,
    data3: 20450,
    data4: [165, 102, 119, 75, 76, 129, 240, 219],
};
pub const LOCAL_D3DFMT_DEFINES: u32 = 1u32;
#[repr(C)]
pub struct MACROBLOCK_DATA {
    pub flags: u32,
    pub motionVectorX: i16,
    pub motionVectorY: i16,
    pub QPDelta: i32,
}
impl ::core::marker::Copy for MACROBLOCK_DATA {}
impl ::core::clone::Clone for MACROBLOCK_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MACROBLOCK_FLAG_DIRTY: u32 = 2u32;
pub const MACROBLOCK_FLAG_HAS_MOTION_VECTOR: u32 = 16u32;
pub const MACROBLOCK_FLAG_HAS_QP: u32 = 32u32;
pub const MACROBLOCK_FLAG_MOTION: u32 = 4u32;
pub const MACROBLOCK_FLAG_SKIP: u32 = 1u32;
pub const MACROBLOCK_FLAG_VIDEO: u32 = 8u32;
pub const MAX_SUBSTREAMS: u32 = 15u32;
pub const MEDIASINK_CANNOT_MATCH_CLOCK: u32 = 2u32;
pub const MEDIASINK_CAN_PREROLL: u32 = 16u32;
pub const MEDIASINK_CLOCK_REQUIRED: u32 = 8u32;
pub const MEDIASINK_FIXED_STREAMS: u32 = 1u32;
pub const MEDIASINK_RATELESS: u32 = 4u32;
pub const MEDIASINK_REQUIRE_REFERENCE_MEDIATYPE: u32 = 32u32;
pub const MEDIASUBTYPE_AVC1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 826496577, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_DOLBY_DDPLUS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2818279343,
    data2: 11522,
    data3: 17147,
    data4: [164, 212, 5, 205, 147, 132, 59, 221],
};
pub const MEDIASUBTYPE_DOLBY_TRUEHD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3945254596, data2: 5694, data3: 19619, data4: [139, 116, 142, 37, 249, 27, 81, 126] };
pub const MEDIASUBTYPE_DTS2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 8193, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_DTS_HD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2732953271, data2: 4009, data3: 18619, data4: [164, 12, 250, 14, 21, 109, 6, 69] };
pub const MEDIASUBTYPE_DTS_HD_HRA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2786771812, data2: 44302, data3: 18244, data4: [137, 255, 33, 60, 224, 223, 136, 4] };
pub const MEDIASUBTYPE_DVM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 8192, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_I420: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808596553, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_M4S2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 844313677, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MP42: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 842289229, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MP43: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 859066445, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MP4S: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1395937357, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MPEG_ADTS_AAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5632, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MPEG_HEAAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5648, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MPEG_LOAS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5634, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MPEG_RAW_AAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5633, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MPG4: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 877088845, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MSAUDIO1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 352, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MSS1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 827544397, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_MSS2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 844321613, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_NOKIA_MPEG_ADTS_AAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5640, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_NOKIA_MPEG_RAW_AAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5641, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_NV11: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 825316942, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_None: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3828804494, data2: 21071, data3: 4558, data4: [159, 83, 0, 32, 175, 11, 167, 112] };
pub const MEDIASUBTYPE_RAW_AAC1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 255, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_V216: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 909193814, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_V410: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808531030, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_VODAFONE_MPEG_ADTS_AAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5642, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_VODAFONE_MPEG_RAW_AAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5643, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMASPDIF: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 356, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMAUDIO2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 353, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMAUDIO3: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 354, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMAUDIO4: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 360, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMAUDIO_LOSSLESS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 355, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMV1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 827739479, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMV2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 844516695, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMV3: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 861293911, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMVA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1096174935, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMVB: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1112952151, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMVP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1347833175, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WMVR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1381387607, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WVC1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 826496599, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_WVP2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 844125783, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_X264: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 875967064, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_Y41T: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1412510809, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_Y42T: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1412576345, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_h264: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 875967080, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_m4s2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 846410861, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_mp42: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 842297453, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_mp43: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 859074669, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_mp4s: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1932816493, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_mpg4: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 879194221, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_v210: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808530550, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_wmv1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 829844855, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_wmv2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 846622071, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_wmv3: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 863399287, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_wmva: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1635151223, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_wmvb: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1651928439, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_wmvp: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1886809463, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_wmvr: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1920363895, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_wvc1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 828601975, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_wvp2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 846231159, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MEDIASUBTYPE_x264: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 875967096, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub type MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS = u32;
pub const MF_EVENT_FLAG_NONE: MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS = 0u32;
pub const MF_EVENT_FLAG_NO_WAIT: MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS = 1u32;
pub const MEDeviceStreamCreated: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 38969807, data2: 13632, data3: 17332, data4: [145, 100, 215, 46, 180, 5, 250, 64] };
pub type MF2DBuffer_LockFlags = i32;
pub const MF2DBuffer_LockFlags_LockTypeMask: MF2DBuffer_LockFlags = 3i32;
pub const MF2DBuffer_LockFlags_Read: MF2DBuffer_LockFlags = 1i32;
pub const MF2DBuffer_LockFlags_Write: MF2DBuffer_LockFlags = 2i32;
pub const MF2DBuffer_LockFlags_ReadWrite: MF2DBuffer_LockFlags = 3i32;
pub const MF2DBuffer_LockFlags_ForceDWORD: MF2DBuffer_LockFlags = 2147483647i32;
pub type MF3DVideoOutputType = i32;
pub const MF3DVideoOutputType_BaseView: MF3DVideoOutputType = 0i32;
pub const MF3DVideoOutputType_Stereo: MF3DVideoOutputType = 1i32;
pub const MFAMRNBByteStreamHandler: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4024836234, data2: 2604, data3: 18938, data4: [138, 1, 55, 104, 181, 89, 182, 218] };
pub const MFAMRNBSinkClassFactory: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2955350360,
    data2: 28882,
    data3: 19547,
    data4: [159, 148, 118, 245, 73, 217, 15, 223],
};
#[repr(C)]
pub struct MFARGB {
    pub rgbBlue: u8,
    pub rgbGreen: u8,
    pub rgbRed: u8,
    pub rgbAlpha: u8,
}
impl ::core::marker::Copy for MFARGB {}
impl ::core::clone::Clone for MFARGB {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFASFINDEXER_APPROX_SEEK_TIME_UNKNOWN: u64 = 18446744073709551615u64;
pub const MFASFINDEXER_NO_FIXED_INTERVAL: u32 = 4294967295u32;
pub const MFASFINDEXER_PER_ENTRY_BYTES_DYNAMIC: u32 = 65535u32;
pub const MFASFINDEXER_READ_FOR_REVERSEPLAYBACK_OUTOFDATASEGMENT: u64 = 18446744073709551615u64;
pub const MFASFINDEXER_TYPE_TIMECODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1233211953, data2: 27565, data3: 17661, data4: [129, 10, 63, 96, 152, 78, 199, 253] };
pub const MFASFMutexType_Bitrate: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1914145836, data2: 58459, data3: 4565, data4: [188, 42, 0, 176, 208, 243, 244, 171] };
pub const MFASFMutexType_Language: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1914145835, data2: 58459, data3: 4565, data4: [188, 42, 0, 176, 208, 243, 244, 171] };
pub const MFASFMutexType_Presentation: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1914145837, data2: 58459, data3: 4565, data4: [188, 42, 0, 176, 208, 243, 244, 171] };
pub const MFASFMutexType_Unknown: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1914145838, data2: 58459, data3: 4565, data4: [188, 42, 0, 176, 208, 243, 244, 171] };
pub const MFASFSPLITTER_PACKET_BOUNDARY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4267198981, data2: 59606, data3: 17123, data4: [177, 118, 241, 33, 23, 5, 251, 111] };
pub const MFASFSampleExtension_ContentType: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3583040544,
    data2: 1980,
    data3: 17260,
    data4: [156, 247, 243, 187, 251, 241, 164, 220],
};
pub const MFASFSampleExtension_Encryption_KeyID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1983341969,
    data2: 31071,
    data3: 19873,
    data4: [134, 237, 157, 70, 236, 161, 9, 169],
};
pub const MFASFSampleExtension_Encryption_SampleID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1721284686, data2: 2810, data3: 17200, data4: [174, 178, 28, 10, 152, 215, 164, 77] };
pub const MFASFSampleExtension_FileName: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3781553166,
    data2: 6637,
    data3: 17879,
    data4: [180, 167, 37, 203, 209, 226, 142, 155],
};
pub const MFASFSampleExtension_OutputCleanPoint: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4146740335, data2: 28340, data3: 20156, data4: [177, 146, 9, 173, 151, 89, 232, 40] };
pub const MFASFSampleExtension_PixelAspectRatio: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 455009620,
    data2: 63978,
    data3: 19400,
    data4: [130, 26, 55, 107, 116, 228, 196, 184],
};
pub const MFASFSampleExtension_SMPTE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 966104556,
    data2: 34407,
    data3: 20013,
    data4: [143, 219, 152, 129, 76, 231, 108, 30],
};
pub const MFASFSampleExtension_SampleDuration: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3334313040,
    data2: 34431,
    data3: 18695,
    data4: [131, 163, 199, 121, 33, 183, 51, 173],
};
pub const MFASF_DEFAULT_BUFFER_WINDOW_MS: u32 = 3000u32;
pub type MFASF_INDEXER_FLAGS = i32;
pub const MFASF_INDEXER_WRITE_NEW_INDEX: MFASF_INDEXER_FLAGS = 1i32;
pub const MFASF_INDEXER_READ_FOR_REVERSEPLAYBACK: MFASF_INDEXER_FLAGS = 2i32;
pub const MFASF_INDEXER_WRITE_FOR_LIVEREAD: MFASF_INDEXER_FLAGS = 4i32;
pub const MFASF_INVALID_STREAM_NUMBER: u32 = 128u32;
pub const MFASF_MAX_STREAM_NUMBER: u32 = 127u32;
pub type MFASF_MULTIPLEXERFLAGS = i32;
pub const MFASF_MULTIPLEXER_AUTOADJUST_BITRATE: MFASF_MULTIPLEXERFLAGS = 1i32;
pub const MFASF_PAYLOADEXTENSION_MAX_SIZE: u32 = 255u32;
pub const MFASF_PAYLOADEXTENSION_VARIABLE_SIZE: u32 = 65535u32;
pub type MFASF_SPLITTERFLAGS = i32;
pub const MFASF_SPLITTER_REVERSE: MFASF_SPLITTERFLAGS = 1i32;
pub const MFASF_SPLITTER_WMDRM: MFASF_SPLITTERFLAGS = 2i32;
pub type MFASF_STREAMSELECTOR_FLAGS = i32;
pub const MFASF_STREAMSELECTOR_DISABLE_THINNING: MFASF_STREAMSELECTOR_FLAGS = 1i32;
pub const MFASF_STREAMSELECTOR_USE_AVERAGE_BITRATE: MFASF_STREAMSELECTOR_FLAGS = 2i32;
pub type MFASYNCRESULT = *mut ::core::ffi::c_void;
pub const MFASYNC_BLOCKING_CALLBACK: u32 = 4u32;
pub const MFASYNC_CALLBACK_QUEUE_ALL: u32 = 4294967295u32;
pub const MFASYNC_CALLBACK_QUEUE_IO: u32 = 3u32;
pub const MFASYNC_CALLBACK_QUEUE_LONG_FUNCTION: u32 = 7u32;
pub const MFASYNC_CALLBACK_QUEUE_MULTITHREADED: u32 = 5u32;
pub const MFASYNC_CALLBACK_QUEUE_PRIVATE_MASK: u32 = 4294901760u32;
pub const MFASYNC_CALLBACK_QUEUE_RT: u32 = 2u32;
pub const MFASYNC_CALLBACK_QUEUE_STANDARD: u32 = 1u32;
pub const MFASYNC_CALLBACK_QUEUE_TIMER: u32 = 4u32;
pub const MFASYNC_CALLBACK_QUEUE_UNDEFINED: u32 = 0u32;
pub const MFASYNC_FAST_IO_PROCESSING_CALLBACK: u32 = 1u32;
pub const MFASYNC_LOCALIZE_REMOTE_CALLBACK: u32 = 16u32;
pub const MFASYNC_REPLY_CALLBACK: u32 = 8u32;
pub const MFASYNC_SIGNAL_CALLBACK: u32 = 2u32;
pub type MFASYNC_WORKQUEUE_TYPE = i32;
pub const MF_STANDARD_WORKQUEUE: MFASYNC_WORKQUEUE_TYPE = 0i32;
pub const MF_WINDOW_WORKQUEUE: MFASYNC_WORKQUEUE_TYPE = 1i32;
pub const MF_MULTITHREADED_WORKQUEUE: MFASYNC_WORKQUEUE_TYPE = 2i32;
#[repr(C)]
pub struct MFAYUVSample {
    pub bCrValue: u8,
    pub bCbValue: u8,
    pub bYValue: u8,
    pub bSampleAlpha8: u8,
}
impl ::core::marker::Copy for MFAYUVSample {}
impl ::core::clone::Clone for MFAYUVSample {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFAudioConstriction = i32;
pub const MFaudioConstrictionOff: MFAudioConstriction = 0i32;
pub const MFaudioConstriction48_16: MFAudioConstriction = 1i32;
pub const MFaudioConstriction44_16: MFAudioConstriction = 2i32;
pub const MFaudioConstriction14_14: MFAudioConstriction = 3i32;
pub const MFaudioConstrictionMute: MFAudioConstriction = 4i32;
#[repr(C)]
pub struct MFAudioDecoderDegradationInfo {
    pub eDegradationReason: MFT_AUDIO_DECODER_DEGRADATION_REASON,
    pub eType: MFT_AUDIO_DECODER_DEGRADATION_TYPE,
}
impl ::core::marker::Copy for MFAudioDecoderDegradationInfo {}
impl ::core::clone::Clone for MFAudioDecoderDegradationInfo {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFAudioFormat_AAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5648, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_AAC_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1100729974,
    data2: 35698,
    data3: 16399,
    data4: [173, 235, 132, 181, 125, 99, 72, 77],
};
pub const MFAudioFormat_ADTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 5632, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_ADTS_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3662242723, data2: 5336, data3: 19919, data4: [146, 183, 25, 62, 184, 67, 99, 219] };
pub const MFAudioFormat_ALAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 27745, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_AMR_NB: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 29537, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_AMR_WB: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 29538, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_AMR_WP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 29539, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_Base: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 0, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_Base_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 948221372, data2: 57975, data3: 17405, data4: [152, 61, 3, 138, 168, 217, 182, 5] };
pub const MFAudioFormat_DRM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 9, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_DTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 8, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_DTS_HD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2732953271, data2: 4009, data3: 18619, data4: [164, 12, 250, 14, 21, 109, 6, 69] };
pub const MFAudioFormat_DTS_LBR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3271454474,
    data2: 20028,
    data3: 19953,
    data4: [155, 96, 80, 134, 48, 145, 228, 185],
};
pub const MFAudioFormat_DTS_RAW: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3765272627, data2: 56134, data3: 4559, data4: [180, 209, 0, 128, 95, 108, 187, 234] };
pub const MFAudioFormat_DTS_UHD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2265055511, data2: 44259, data3: 17118, data4: [183, 62, 198, 86, 112, 98, 99, 248] };
pub const MFAudioFormat_DTS_UHDY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2610743808,
    data2: 37305,
    data3: 19660,
    data4: [136, 58, 143, 120, 122, 195, 204, 134],
};
pub const MFAudioFormat_DTS_XLL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1169390619,
    data2: 35952,
    data3: 20057,
    data4: [167, 190, 161, 228, 44, 129, 200, 13],
};
pub const MFAudioFormat_Dolby_AC3: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3765272620, data2: 56134, data3: 4559, data4: [180, 209, 0, 128, 95, 108, 187, 234] };
pub const MFAudioFormat_Dolby_AC3_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2540059264,
    data2: 36859,
    data3: 17477,
    data4: [166, 186, 121, 45, 144, 143, 73, 127],
};
pub const MFAudioFormat_Dolby_AC3_SPDIF: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 146, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_Dolby_AC4: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 44096, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_Dolby_AC4_V1: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 918000252,
    data2: 15751,
    data3: 18986,
    data4: [145, 150, 162, 26, 217, 233, 53, 230],
};
pub const MFAudioFormat_Dolby_AC4_V1_ES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2643315910,
    data2: 53590,
    data3: 20408,
    data4: [151, 156, 168, 91, 231, 210, 29, 250],
};
pub const MFAudioFormat_Dolby_AC4_V2: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2040050336,
    data2: 6109,
    data3: 18870,
    data4: [141, 250, 155, 39, 133, 82, 162, 172],
};
pub const MFAudioFormat_Dolby_AC4_V2_ES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2119748089,
    data2: 45168,
    data3: 17908,
    data4: [140, 205, 169, 154, 4, 23, 193, 172],
};
pub const MFAudioFormat_Dolby_DDPlus: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2818279343,
    data2: 11522,
    data3: 17147,
    data4: [164, 212, 5, 205, 147, 132, 59, 221],
};
pub const MFAudioFormat_FLAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 61868, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_Float: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_Float_SpatialObjects: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4198092180,
    data2: 48228,
    data3: 19121,
    data4: [155, 113, 220, 208, 157, 90, 126, 122],
};
pub const MFAudioFormat_LPCM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3765272626, data2: 56134, data3: 4559, data4: [180, 209, 0, 128, 95, 108, 187, 234] };
pub const MFAudioFormat_MP3: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 85, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_MPEG: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 80, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_MSP1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 10, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_Opus: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 28751, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_PCM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_PCM_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2783444737, data2: 33809, data3: 19148, data4: [168, 101, 95, 73, 65, 40, 141, 128] };
pub const MFAudioFormat_Vorbis: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2368721163, data2: 22593, data3: 19051, data4: [137, 5, 88, 143, 236, 26, 222, 217] };
pub const MFAudioFormat_WMASPDIF: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 356, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_WMAudioV8: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 353, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_WMAudioV9: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 354, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFAudioFormat_WMAudio_Lossless: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 355, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
#[repr(C)]
pub struct MFBYTESTREAM_BUFFERING_PARAMS {
    pub cbTotalFileSize: u64,
    pub cbPlayableDataSize: u64,
    pub prgBuckets: *mut MF_LEAKY_BUCKET_PAIR,
    pub cBuckets: u32,
    pub qwNetBufferingTime: u64,
    pub qwExtraBufferingTimeDuringSeek: u64,
    pub qwPlayDuration: u64,
    pub dRate: f32,
}
impl ::core::marker::Copy for MFBYTESTREAM_BUFFERING_PARAMS {}
impl ::core::clone::Clone for MFBYTESTREAM_BUFFERING_PARAMS {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFBYTESTREAM_DOES_NOT_USE_NETWORK: u32 = 2048u32;
pub const MFBYTESTREAM_HAS_SLOW_SEEK: u32 = 256u32;
pub const MFBYTESTREAM_IS_DIRECTORY: u32 = 128u32;
pub const MFBYTESTREAM_IS_PARTIALLY_DOWNLOADED: u32 = 512u32;
pub const MFBYTESTREAM_IS_READABLE: u32 = 1u32;
pub const MFBYTESTREAM_IS_REMOTE: u32 = 8u32;
pub const MFBYTESTREAM_IS_SEEKABLE: u32 = 4u32;
pub const MFBYTESTREAM_IS_WRITABLE: u32 = 2u32;
pub const MFBYTESTREAM_SEEK_FLAG_CANCEL_PENDING_IO: u32 = 1u32;
pub type MFBYTESTREAM_SEEK_ORIGIN = i32;
pub const msoBegin: MFBYTESTREAM_SEEK_ORIGIN = 0i32;
pub const msoCurrent: MFBYTESTREAM_SEEK_ORIGIN = 1i32;
pub const MFBYTESTREAM_SHARE_WRITE: u32 = 1024u32;
pub const MFCAPTURE_METADATA_SCANLINE_VERTICAL: u32 = 4u32;
pub const MFCAPTURE_METADATA_SCAN_BOTTOM_TOP: u32 = 2u32;
pub const MFCAPTURE_METADATA_SCAN_RIGHT_LEFT: u32 = 1u32;
pub type MFCLOCK_CHARACTERISTICS_FLAGS = i32;
pub const MFCLOCK_CHARACTERISTICS_FLAG_FREQUENCY_10MHZ: MFCLOCK_CHARACTERISTICS_FLAGS = 2i32;
pub const MFCLOCK_CHARACTERISTICS_FLAG_ALWAYS_RUNNING: MFCLOCK_CHARACTERISTICS_FLAGS = 4i32;
pub const MFCLOCK_CHARACTERISTICS_FLAG_IS_SYSTEM_CLOCK: MFCLOCK_CHARACTERISTICS_FLAGS = 8i32;
pub const MFCLOCK_FREQUENCY_HNS: u32 = 10000000u32;
pub const MFCLOCK_JITTER_DPC: u32 = 4000u32;
pub const MFCLOCK_JITTER_ISR: u32 = 1000u32;
pub const MFCLOCK_JITTER_PASSIVE: u32 = 10000u32;
#[repr(C)]
pub struct MFCLOCK_PROPERTIES {
    pub qwCorrelationRate: u64,
    pub guidClockId: ::windows_sys::core::GUID,
    pub dwClockFlags: u32,
    pub qwClockFrequency: u64,
    pub dwClockTolerance: u32,
    pub dwClockJitter: u32,
}
impl ::core::marker::Copy for MFCLOCK_PROPERTIES {}
impl ::core::clone::Clone for MFCLOCK_PROPERTIES {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFCLOCK_RELATIONAL_FLAGS = i32;
pub const MFCLOCK_RELATIONAL_FLAG_JITTER_NEVER_AHEAD: MFCLOCK_RELATIONAL_FLAGS = 1i32;
pub type MFCLOCK_STATE = i32;
pub const MFCLOCK_STATE_INVALID: MFCLOCK_STATE = 0i32;
pub const MFCLOCK_STATE_RUNNING: MFCLOCK_STATE = 1i32;
pub const MFCLOCK_STATE_STOPPED: MFCLOCK_STATE = 2i32;
pub const MFCLOCK_STATE_PAUSED: MFCLOCK_STATE = 3i32;
pub const MFCLOCK_TOLERANCE_UNKNOWN: u32 = 50000u32;
pub const MFCONNECTOR_AGP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2889543520, data2: 52803, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_COMPONENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075563, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_COMPOSITE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075562, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_DISPLAYPORT_EMBEDDED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075571, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_DISPLAYPORT_EXTERNAL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075570, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_DVI: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075564, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_D_JPN: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075568, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_HDMI: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075565, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_LVDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075566, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_MIRACAST: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075575, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_PCI: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2889543517, data2: 52803, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_PCIX: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2889543518, data2: 52803, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_PCI_Express: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2889543519, data2: 52803, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_SDI: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075569, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_SPDIF: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 194291474,
    data2: 44350,
    data3: 19694,
    data4: [131, 206, 206, 50, 227, 219, 101, 34],
};
pub const MFCONNECTOR_SVIDEO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075561, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_TRANSPORT_AGNOSTIC_DIGITAL_MODE_A: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075576, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_TRANSPORT_AGNOSTIC_DIGITAL_MODE_B: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075577, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_UDI_EMBEDDED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075573, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_UDI_EXTERNAL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075572, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_UNKNOWN: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2889543516, data2: 52803, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONNECTOR_VGA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1473075560, data2: 52807, data3: 4569, data4: [146, 219, 0, 11, 219, 40, 255, 152] };
pub const MFCONTENTPROTECTIONDEVICE_FUNCTIONID_START: u32 = 67108864u32;
#[repr(C)]
pub struct MFCONTENTPROTECTIONDEVICE_INPUT_DATA {
    pub HWProtectionFunctionID: u32,
    pub PrivateDataByteCount: u32,
    pub HWProtectionDataByteCount: u32,
    pub Reserved: u32,
    pub InputData: [u8; 4],
}
impl ::core::marker::Copy for MFCONTENTPROTECTIONDEVICE_INPUT_DATA {}
impl ::core::clone::Clone for MFCONTENTPROTECTIONDEVICE_INPUT_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFCONTENTPROTECTIONDEVICE_OUTPUT_DATA {
    pub PrivateDataByteCount: u32,
    pub MaxHWProtectionDataByteCount: u32,
    pub HWProtectionDataByteCount: u32,
    pub Status: ::windows_sys::core::HRESULT,
    pub TransportTimeInHundredsOfNanoseconds: i64,
    pub ExecutionTimeInHundredsOfNanoseconds: i64,
    pub OutputData: [u8; 4],
}
impl ::core::marker::Copy for MFCONTENTPROTECTIONDEVICE_OUTPUT_DATA {}
impl ::core::clone::Clone for MFCONTENTPROTECTIONDEVICE_OUTPUT_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFCONTENTPROTECTIONDEVICE_REALTIMECLIENT_DATA {
    pub TaskIndex: u32,
    pub ClassName: [u16; 260],
    pub BasePriority: i32,
}
impl ::core::marker::Copy for MFCONTENTPROTECTIONDEVICE_REALTIMECLIENT_DATA {}
impl ::core::clone::Clone for MFCONTENTPROTECTIONDEVICE_REALTIMECLIENT_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFCONTENTPROTECTIONDEVICE_REALTIMECLIENT_DATA_FUNCTIONID: u32 = 67108864u32;
#[repr(C)]
pub struct MFCameraExtrinsic_CalibratedTransform {
    pub CalibrationId: ::windows_sys::core::GUID,
    pub Position: MF_FLOAT3,
    pub Orientation: MF_QUATERNION,
}
impl ::core::marker::Copy for MFCameraExtrinsic_CalibratedTransform {}
impl ::core::clone::Clone for MFCameraExtrinsic_CalibratedTransform {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFCameraExtrinsics {
    pub TransformCount: u32,
    pub CalibratedTransforms: [MFCameraExtrinsic_CalibratedTransform; 1],
}
impl ::core::marker::Copy for MFCameraExtrinsics {}
impl ::core::clone::Clone for MFCameraExtrinsics {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFCameraIntrinsic_CameraModel {
    pub FocalLength_x: f32,
    pub FocalLength_y: f32,
    pub PrincipalPoint_x: f32,
    pub PrincipalPoint_y: f32,
}
impl ::core::marker::Copy for MFCameraIntrinsic_CameraModel {}
impl ::core::clone::Clone for MFCameraIntrinsic_CameraModel {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFCameraIntrinsic_DistortionModel {
    pub Radial_k1: f32,
    pub Radial_k2: f32,
    pub Radial_k3: f32,
    pub Tangential_p1: f32,
    pub Tangential_p2: f32,
}
impl ::core::marker::Copy for MFCameraIntrinsic_DistortionModel {}
impl ::core::clone::Clone for MFCameraIntrinsic_DistortionModel {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFCameraIntrinsic_DistortionModel6KT {
    pub Radial_k1: f32,
    pub Radial_k2: f32,
    pub Radial_k3: f32,
    pub Radial_k4: f32,
    pub Radial_k5: f32,
    pub Radial_k6: f32,
    pub Tangential_p1: f32,
    pub Tangential_p2: f32,
}
impl ::core::marker::Copy for MFCameraIntrinsic_DistortionModel6KT {}
impl ::core::clone::Clone for MFCameraIntrinsic_DistortionModel6KT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFCameraIntrinsic_DistortionModelArcTan {
    pub Radial_k0: f32,
    pub DistortionCenter_x: f32,
    pub DistortionCenter_y: f32,
    pub Tangential_x: f32,
    pub Tangential_y: f32,
}
impl ::core::marker::Copy for MFCameraIntrinsic_DistortionModelArcTan {}
impl ::core::clone::Clone for MFCameraIntrinsic_DistortionModelArcTan {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFCameraIntrinsic_DistortionModelType = i32;
pub const MFCameraIntrinsic_DistortionModelType_6KT: MFCameraIntrinsic_DistortionModelType = 0i32;
pub const MFCameraIntrinsic_DistortionModelType_ArcTan: MFCameraIntrinsic_DistortionModelType = 1i32;
#[repr(C)]
pub struct MFCameraIntrinsic_PinholeCameraModel {
    pub FocalLength: MF_FLOAT2,
    pub PrincipalPoint: MF_FLOAT2,
}
impl ::core::marker::Copy for MFCameraIntrinsic_PinholeCameraModel {}
impl ::core::clone::Clone for MFCameraIntrinsic_PinholeCameraModel {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFCameraOcclusionState = i32;
pub const MFCameraOcclusionState_Open: MFCameraOcclusionState = 0i32;
pub const MFCameraOcclusionState_OccludedByLid: MFCameraOcclusionState = 1i32;
pub const MFCameraOcclusionState_OccludedByCameraHardware: MFCameraOcclusionState = 2i32;
pub type MFDepthMeasurement = i32;
pub const DistanceToFocalPlane: MFDepthMeasurement = 0i32;
pub const DistanceToOpticalCenter: MFDepthMeasurement = 1i32;
pub const MFENABLETYPE_MF_RebootRequired: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1833778507, data2: 3790, data3: 18002, data4: [139, 58, 242, 210, 66, 96, 216, 135] };
pub const MFENABLETYPE_MF_UpdateRevocationInformation: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3847794869,
    data2: 46020,
    data3: 17568,
    data4: [146, 76, 80, 209, 120, 147, 35, 133],
};
pub const MFENABLETYPE_MF_UpdateUntrustedComponent: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2558129110,
    data2: 52962,
    data3: 18662,
    data4: [181, 115, 151, 103, 171, 23, 47, 22],
};
pub const MFENABLETYPE_WMDRMV1_LicenseAcquisition: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1341583023,
    data2: 2883,
    data3: 18327,
    data4: [155, 133, 171, 243, 24, 21, 231, 176],
};
pub const MFENABLETYPE_WMDRMV7_Individualization: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2899494986, data2: 45827, data3: 20325, data4: [188, 44, 44, 132, 141, 1, 169, 137] };
pub const MFENABLETYPE_WMDRMV7_LicenseAcquisition: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3344095, data2: 18950, data3: 18564, data4: [160, 151, 239, 109, 34, 236, 132, 163] };
pub const MFEVRDLL: u32 = 0u32;
#[repr(C)]
pub struct MFExtendedCameraIntrinsic_IntrinsicModel {
    pub Width: u32,
    pub Height: u32,
    pub SplitFrameId: u32,
    pub CameraModel: MFCameraIntrinsic_CameraModel,
}
impl ::core::marker::Copy for MFExtendedCameraIntrinsic_IntrinsicModel {}
impl ::core::clone::Clone for MFExtendedCameraIntrinsic_IntrinsicModel {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFFLACBytestreamHandler: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 239194040, data2: 1286, data3: 16628, data4: [165, 22, 119, 204, 35, 100, 45, 145] };
pub const MFFLACSinkClassFactory: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2100938095,
    data2: 24693,
    data3: 18377,
    data4: [155, 174, 140, 249, 229, 49, 181, 245],
};
#[repr(C)]
pub struct MFFOLDDOWN_MATRIX {
    pub cbSize: u32,
    pub cSrcChannels: u32,
    pub cDstChannels: u32,
    pub dwChannelMask: u32,
    pub Coeff: [i32; 64],
}
impl ::core::marker::Copy for MFFOLDDOWN_MATRIX {}
impl ::core::clone::Clone for MFFOLDDOWN_MATRIX {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFFrameSourceTypes = i32;
pub const MFFrameSourceTypes_Color: MFFrameSourceTypes = 1i32;
pub const MFFrameSourceTypes_Infrared: MFFrameSourceTypes = 2i32;
pub const MFFrameSourceTypes_Depth: MFFrameSourceTypes = 4i32;
pub const MFFrameSourceTypes_Image: MFFrameSourceTypes = 8i32;
pub const MFFrameSourceTypes_Custom: MFFrameSourceTypes = 128i32;
#[repr(C)]
pub struct MFINPUTTRUSTAUTHORITY_ACCESS_ACTION {
    pub Action: MFPOLICYMANAGER_ACTION,
    pub pbTicket: *mut u8,
    pub cbTicket: u32,
}
impl ::core::marker::Copy for MFINPUTTRUSTAUTHORITY_ACCESS_ACTION {}
impl ::core::clone::Clone for MFINPUTTRUSTAUTHORITY_ACCESS_ACTION {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFINPUTTRUSTAUTHORITY_ACCESS_PARAMS {
    pub dwSize: u32,
    pub dwVer: u32,
    pub cbSignatureOffset: u32,
    pub cbSignatureSize: u32,
    pub cbExtensionOffset: u32,
    pub cbExtensionSize: u32,
    pub cActions: u32,
    pub rgOutputActions: [MFINPUTTRUSTAUTHORITY_ACCESS_ACTION; 1],
}
impl ::core::marker::Copy for MFINPUTTRUSTAUTHORITY_ACCESS_PARAMS {}
impl ::core::clone::Clone for MFINPUTTRUSTAUTHORITY_ACCESS_PARAMS {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFImageFormat_JPEG: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 434415018, data2: 22114, data3: 20421, data4: [160, 192, 23, 88, 2, 142, 16, 87] };
pub const MFImageFormat_RGB32: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 22, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub type MFMEDIASOURCE_CHARACTERISTICS = i32;
pub const MFMEDIASOURCE_IS_LIVE: MFMEDIASOURCE_CHARACTERISTICS = 1i32;
pub const MFMEDIASOURCE_CAN_SEEK: MFMEDIASOURCE_CHARACTERISTICS = 2i32;
pub const MFMEDIASOURCE_CAN_PAUSE: MFMEDIASOURCE_CHARACTERISTICS = 4i32;
pub const MFMEDIASOURCE_HAS_SLOW_SEEK: MFMEDIASOURCE_CHARACTERISTICS = 8i32;
pub const MFMEDIASOURCE_HAS_MULTIPLE_PRESENTATIONS: MFMEDIASOURCE_CHARACTERISTICS = 16i32;
pub const MFMEDIASOURCE_CAN_SKIPFORWARD: MFMEDIASOURCE_CHARACTERISTICS = 32i32;
pub const MFMEDIASOURCE_CAN_SKIPBACKWARD: MFMEDIASOURCE_CHARACTERISTICS = 64i32;
pub const MFMEDIASOURCE_DOES_NOT_USE_NETWORK: MFMEDIASOURCE_CHARACTERISTICS = 128i32;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MFMPEG2DLNASINKSTATS {
    pub cBytesWritten: u64,
    pub fPAL: super::super::Foundation::BOOL,
    pub fccVideo: u32,
    pub dwVideoWidth: u32,
    pub dwVideoHeight: u32,
    pub cVideoFramesReceived: u64,
    pub cVideoFramesEncoded: u64,
    pub cVideoFramesSkipped: u64,
    pub cBlackVideoFramesEncoded: u64,
    pub cVideoFramesDuplicated: u64,
    pub cAudioSamplesPerSec: u32,
    pub cAudioChannels: u32,
    pub cAudioBytesReceived: u64,
    pub cAudioFramesEncoded: u64,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MFMPEG2DLNASINKSTATS {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MFMPEG2DLNASINKSTATS {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFMPEG4Format_Base: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 0, data2: 30330, data3: 18765, data4: [180, 120, 242, 157, 37, 220, 144, 55] };
#[repr(C)]
pub struct MFMediaKeyStatus {
    pub pbKeyId: *mut u8,
    pub cbKeyId: u32,
    pub eMediaKeyStatus: MF_MEDIAKEY_STATUS,
}
impl ::core::marker::Copy for MFMediaKeyStatus {}
impl ::core::clone::Clone for MFMediaKeyStatus {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFMediaType_Audio: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1935963489, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFMediaType_Binary: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1914145829, data2: 58459, data3: 4565, data4: [188, 42, 0, 176, 208, 243, 244, 171] };
pub const MFMediaType_Default: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2175013606, data2: 33027, data3: 19206, data4: [133, 127, 24, 98, 120, 16, 36, 172] };
pub const MFMediaType_FileTransfer: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1914145830, data2: 58459, data3: 4565, data4: [188, 42, 0, 176, 208, 243, 244, 171] };
pub const MFMediaType_HTML: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1914145828, data2: 58459, data3: 4565, data4: [188, 42, 0, 176, 208, 243, 244, 171] };
pub const MFMediaType_Image: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1914145827, data2: 58459, data3: 4565, data4: [188, 42, 0, 176, 208, 243, 244, 171] };
pub const MFMediaType_Metadata: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 747610636,
    data2: 33467,
    data3: 18306,
    data4: [144, 160, 152, 162, 165, 189, 142, 248],
};
pub const MFMediaType_MultiplexedFrames: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1856324272, data2: 10271, data3: 16945, data4: [164, 100, 254, 47, 80, 34, 80, 28] };
pub const MFMediaType_Perception: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1501558521, data2: 28322, data3: 18032, data4: [133, 180, 234, 132, 7, 63, 233, 64] };
pub const MFMediaType_Protected: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2068541414,
    data2: 40196,
    data3: 17556,
    data4: [190, 20, 126, 11, 208, 118, 200, 228],
};
pub const MFMediaType_SAMI: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3868617120, data2: 15821, data3: 16587, data4: [158, 46, 55, 8, 56, 124, 6, 22] };
pub const MFMediaType_Script: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1914145826, data2: 58459, data3: 4565, data4: [188, 42, 0, 176, 208, 243, 244, 171] };
pub const MFMediaType_Stream: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3828804483, data2: 21071, data3: 4558, data4: [159, 83, 0, 32, 175, 11, 167, 112] };
pub const MFMediaType_Subtitle: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2798728577, data2: 60752, data3: 20069, data4: [174, 8, 38, 6, 85, 118, 170, 204] };
pub const MFMediaType_Video: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1935960438, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFNETSOURCE_ACCELERATEDSTREAMINGDURATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294903, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_AUTORECONNECTLIMIT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294906, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_AUTORECONNECTPROGRESS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294914, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_BROWSERUSERAGENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294923, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_BROWSERWEBPAGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294924, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_BUFFERINGTIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294902, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_CACHEENABLED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294905, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub type MFNETSOURCE_CACHE_STATE = i32;
pub const MFNETSOURCE_CACHE_UNAVAILABLE: MFNETSOURCE_CACHE_STATE = 0i32;
pub const MFNETSOURCE_CACHE_ACTIVE_WRITING: MFNETSOURCE_CACHE_STATE = 1i32;
pub const MFNETSOURCE_CACHE_ACTIVE_COMPLETE: MFNETSOURCE_CACHE_STATE = 2i32;
pub const MFNETSOURCE_CLIENTGUID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1621279910,
    data2: 61847,
    data3: 19476,
    data4: [165, 191, 136, 131, 13, 36, 88, 175],
};
pub const MFNETSOURCE_CONNECTIONBANDWIDTH: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294904, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_CREDENTIAL_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294912, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_CROSS_ORIGIN_SUPPORT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2554470524,
    data2: 45100,
    data3: 17009,
    data4: [162, 252, 114, 228, 147, 8, 229, 194],
};
pub const MFNETSOURCE_DRMNET_LICENSE_REPRESENTATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1206575549,
    data2: 48638,
    data3: 17122,
    data4: [130, 243, 84, 164, 140, 23, 150, 45],
};
pub const MFNETSOURCE_ENABLE_DOWNLOAD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294941, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_ENABLE_HTTP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294937, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_ENABLE_MSB: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294934, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_ENABLE_PRIVATEMODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2185722328,
    data2: 61835,
    data3: 17413,
    data4: [140, 241, 70, 79, 181, 170, 143, 113],
};
pub const MFNETSOURCE_ENABLE_RTSP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294936, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_ENABLE_STREAMING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294940, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_ENABLE_TCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294933, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_ENABLE_UDP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294932, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_FRIENDLYNAME: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1529509719, data2: 48235, data3: 17534, data4: [170, 6, 13, 218, 28, 100, 110, 47] };
pub const MFNETSOURCE_HOSTEXE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294927, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_HOSTVERSION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294929, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_HTTP_DOWNLOAD_SESSION_PROVIDER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2102724638, data2: 12413, data3: 19821, data4: [166, 99, 169, 59, 233, 124, 75, 92] };
pub const MFNETSOURCE_LOGPARAMS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1687382760, data2: 37912, data3: 17722, data4: [140, 218, 62, 10, 102, 139, 53, 59] };
pub const MFNETSOURCE_LOGURL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294931, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_MAXBUFFERTIMEMS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1082860774,
    data2: 16440,
    data3: 17409,
    data4: [181, 178, 254, 112, 26, 158, 191, 16],
};
pub const MFNETSOURCE_MAXUDPACCELERATEDSTREAMINGDURATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1252731001, data2: 48097, data3: 18836, data4: [159, 240, 84, 149, 189, 37, 1, 41] };
pub const MFNETSOURCE_PEERMANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1219664603,
    data2: 65215,
    data3: 17902,
    data4: [169, 191, 239, 184, 28, 73, 46, 252],
};
pub const MFNETSOURCE_PLAYERID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294926, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PLAYERUSERAGENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294930, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PLAYERVERSION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294925, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PPBANDWIDTH: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294913, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PREVIEWMODEENABLED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294911, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PROTOCOL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294909, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub type MFNETSOURCE_PROTOCOL_TYPE = i32;
pub const MFNETSOURCE_UNDEFINED: MFNETSOURCE_PROTOCOL_TYPE = 0i32;
pub const MFNETSOURCE_HTTP: MFNETSOURCE_PROTOCOL_TYPE = 1i32;
pub const MFNETSOURCE_RTSP: MFNETSOURCE_PROTOCOL_TYPE = 2i32;
pub const MFNETSOURCE_FILE: MFNETSOURCE_PROTOCOL_TYPE = 3i32;
pub const MFNETSOURCE_MULTICAST: MFNETSOURCE_PROTOCOL_TYPE = 4i32;
pub const MFNETSOURCE_PROXYBYPASSFORLOCAL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294918, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PROXYEXCEPTIONLIST: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294917, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PROXYHOSTNAME: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294916, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PROXYINFO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294939, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PROXYLOCATORFACTORY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294915, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PROXYPORT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294920, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PROXYRERUNAUTODETECTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294921, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_PROXYSETTINGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294919, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_RESENDSENABLED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294907, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_RESOURCE_FILTER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2170359798,
    data2: 9818,
    data3: 17527,
    data4: [158, 70, 123, 128, 173, 128, 181, 251],
};
pub const MFNETSOURCE_SSLCERTIFICATE_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1441188647,
    data2: 59035,
    data3: 16999,
    data4: [148, 12, 45, 126, 197, 187, 138, 15],
};
pub const MFNETSOURCE_STATISTICS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294900, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub type MFNETSOURCE_STATISTICS_IDS = i32;
pub const MFNETSOURCE_RECVPACKETS_ID: MFNETSOURCE_STATISTICS_IDS = 0i32;
pub const MFNETSOURCE_LOSTPACKETS_ID: MFNETSOURCE_STATISTICS_IDS = 1i32;
pub const MFNETSOURCE_RESENDSREQUESTED_ID: MFNETSOURCE_STATISTICS_IDS = 2i32;
pub const MFNETSOURCE_RESENDSRECEIVED_ID: MFNETSOURCE_STATISTICS_IDS = 3i32;
pub const MFNETSOURCE_RECOVEREDBYECCPACKETS_ID: MFNETSOURCE_STATISTICS_IDS = 4i32;
pub const MFNETSOURCE_RECOVEREDBYRTXPACKETS_ID: MFNETSOURCE_STATISTICS_IDS = 5i32;
pub const MFNETSOURCE_OUTPACKETS_ID: MFNETSOURCE_STATISTICS_IDS = 6i32;
pub const MFNETSOURCE_RECVRATE_ID: MFNETSOURCE_STATISTICS_IDS = 7i32;
pub const MFNETSOURCE_AVGBANDWIDTHBPS_ID: MFNETSOURCE_STATISTICS_IDS = 8i32;
pub const MFNETSOURCE_BYTESRECEIVED_ID: MFNETSOURCE_STATISTICS_IDS = 9i32;
pub const MFNETSOURCE_PROTOCOL_ID: MFNETSOURCE_STATISTICS_IDS = 10i32;
pub const MFNETSOURCE_TRANSPORT_ID: MFNETSOURCE_STATISTICS_IDS = 11i32;
pub const MFNETSOURCE_CACHE_STATE_ID: MFNETSOURCE_STATISTICS_IDS = 12i32;
pub const MFNETSOURCE_LINKBANDWIDTH_ID: MFNETSOURCE_STATISTICS_IDS = 13i32;
pub const MFNETSOURCE_CONTENTBITRATE_ID: MFNETSOURCE_STATISTICS_IDS = 14i32;
pub const MFNETSOURCE_SPEEDFACTOR_ID: MFNETSOURCE_STATISTICS_IDS = 15i32;
pub const MFNETSOURCE_BUFFERSIZE_ID: MFNETSOURCE_STATISTICS_IDS = 16i32;
pub const MFNETSOURCE_BUFFERPROGRESS_ID: MFNETSOURCE_STATISTICS_IDS = 17i32;
pub const MFNETSOURCE_LASTBWSWITCHTS_ID: MFNETSOURCE_STATISTICS_IDS = 18i32;
pub const MFNETSOURCE_SEEKRANGESTART_ID: MFNETSOURCE_STATISTICS_IDS = 19i32;
pub const MFNETSOURCE_SEEKRANGEEND_ID: MFNETSOURCE_STATISTICS_IDS = 20i32;
pub const MFNETSOURCE_BUFFERINGCOUNT_ID: MFNETSOURCE_STATISTICS_IDS = 21i32;
pub const MFNETSOURCE_INCORRECTLYSIGNEDPACKETS_ID: MFNETSOURCE_STATISTICS_IDS = 22i32;
pub const MFNETSOURCE_SIGNEDSESSION_ID: MFNETSOURCE_STATISTICS_IDS = 23i32;
pub const MFNETSOURCE_MAXBITRATE_ID: MFNETSOURCE_STATISTICS_IDS = 24i32;
pub const MFNETSOURCE_RECEPTION_QUALITY_ID: MFNETSOURCE_STATISTICS_IDS = 25i32;
pub const MFNETSOURCE_RECOVEREDPACKETS_ID: MFNETSOURCE_STATISTICS_IDS = 26i32;
pub const MFNETSOURCE_VBR_ID: MFNETSOURCE_STATISTICS_IDS = 27i32;
pub const MFNETSOURCE_DOWNLOADPROGRESS_ID: MFNETSOURCE_STATISTICS_IDS = 28i32;
pub const MFNETSOURCE_UNPREDEFINEDPROTOCOLNAME_ID: MFNETSOURCE_STATISTICS_IDS = 29i32;
pub const MFNETSOURCE_STATISTICS_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294901, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_STREAM_LANGUAGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2595504920,
    data2: 63437,
    data3: 20269,
    data4: [141, 109, 250, 53, 180, 146, 206, 203],
};
pub const MFNETSOURCE_THINNINGENABLED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294908, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub const MFNETSOURCE_TRANSPORT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294910, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub type MFNETSOURCE_TRANSPORT_TYPE = i32;
pub const MFNETSOURCE_UDP: MFNETSOURCE_TRANSPORT_TYPE = 0i32;
pub const MFNETSOURCE_TCP: MFNETSOURCE_TRANSPORT_TYPE = 1i32;
pub const MFNETSOURCE_UDP_PORT_RANGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1018294938, data2: 1285, data3: 19549, data4: [174, 113, 10, 85, 99, 68, 239, 161] };
pub type MFNET_PROXYSETTINGS = i32;
pub const MFNET_PROXYSETTING_NONE: MFNET_PROXYSETTINGS = 0i32;
pub const MFNET_PROXYSETTING_MANUAL: MFNET_PROXYSETTINGS = 1i32;
pub const MFNET_PROXYSETTING_AUTO: MFNET_PROXYSETTINGS = 2i32;
pub const MFNET_PROXYSETTING_BROWSER: MFNET_PROXYSETTINGS = 3i32;
pub const MFNET_SAVEJOB_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3092928639,
    data2: 15618,
    data3: 20050,
    data4: [149, 101, 85, 211, 236, 30, 127, 247],
};
pub type MFNetAuthenticationFlags = i32;
pub const MFNET_AUTHENTICATION_PROXY: MFNetAuthenticationFlags = 1i32;
pub const MFNET_AUTHENTICATION_CLEAR_TEXT: MFNetAuthenticationFlags = 2i32;
pub const MFNET_AUTHENTICATION_LOGGED_ON_USER: MFNetAuthenticationFlags = 4i32;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MFNetCredentialManagerGetParam {
    pub hrOp: ::windows_sys::core::HRESULT,
    pub fAllowLoggedOnUser: super::super::Foundation::BOOL,
    pub fClearTextPackage: super::super::Foundation::BOOL,
    pub pszUrl: super::super::Foundation::PWSTR,
    pub pszSite: super::super::Foundation::PWSTR,
    pub pszRealm: super::super::Foundation::PWSTR,
    pub pszPackage: super::super::Foundation::PWSTR,
    pub nRetries: i32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MFNetCredentialManagerGetParam {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MFNetCredentialManagerGetParam {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFNetCredentialOptions = i32;
pub const MFNET_CREDENTIAL_SAVE: MFNetCredentialOptions = 1i32;
pub const MFNET_CREDENTIAL_DONT_CACHE: MFNetCredentialOptions = 2i32;
pub const MFNET_CREDENTIAL_ALLOW_CLEAR_TEXT: MFNetCredentialOptions = 4i32;
pub type MFNetCredentialRequirements = i32;
pub const REQUIRE_PROMPT: MFNetCredentialRequirements = 1i32;
pub const REQUIRE_SAVE_SELECTED: MFNetCredentialRequirements = 2i32;
pub type MFNominalRange = i32;
pub const MFNominalRange_Unknown: MFNominalRange = 0i32;
pub const MFNominalRange_Normal: MFNominalRange = 1i32;
pub const MFNominalRange_Wide: MFNominalRange = 2i32;
pub const MFNominalRange_0_255: MFNominalRange = 1i32;
pub const MFNominalRange_16_235: MFNominalRange = 2i32;
pub const MFNominalRange_48_208: MFNominalRange = 3i32;
pub const MFNominalRange_64_127: MFNominalRange = 4i32;
pub const MFNominalRange_Last: MFNominalRange = 5i32;
pub const MFNominalRange_ForceDWORD: MFNominalRange = 2147483647i32;
#[repr(C)]
pub struct MFOffset {
    pub fract: u16,
    pub value: i16,
}
impl ::core::marker::Copy for MFOffset {}
impl ::core::clone::Clone for MFOffset {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFPERIODICCALLBACK = unsafe extern "system" fn(pcontext: ::windows_sys::core::IUnknown);
pub type MFPMPSESSION_CREATION_FLAGS = i32;
pub const MFPMPSESSION_UNPROTECTED_PROCESS: MFPMPSESSION_CREATION_FLAGS = 1i32;
pub const MFPMPSESSION_IN_PROCESS: MFPMPSESSION_CREATION_FLAGS = 2i32;
pub type MFPOLICYMANAGER_ACTION = i32;
pub const PEACTION_NO: MFPOLICYMANAGER_ACTION = 0i32;
pub const PEACTION_PLAY: MFPOLICYMANAGER_ACTION = 1i32;
pub const PEACTION_COPY: MFPOLICYMANAGER_ACTION = 2i32;
pub const PEACTION_EXPORT: MFPOLICYMANAGER_ACTION = 3i32;
pub const PEACTION_EXTRACT: MFPOLICYMANAGER_ACTION = 4i32;
pub const PEACTION_RESERVED1: MFPOLICYMANAGER_ACTION = 5i32;
pub const PEACTION_RESERVED2: MFPOLICYMANAGER_ACTION = 6i32;
pub const PEACTION_RESERVED3: MFPOLICYMANAGER_ACTION = 7i32;
pub const PEACTION_LAST: MFPOLICYMANAGER_ACTION = 7i32;
pub const MFPROTECTIONATTRIBUTE_BEST_EFFORT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3370148657, data2: 30192, data3: 20161, data4: [142, 119, 23, 87, 143, 119, 59, 70] };
pub const MFPROTECTIONATTRIBUTE_CONSTRICTVIDEO_IMAGESIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 8681212, data2: 19288, data3: 19840, data4: [167, 144, 231, 41, 118, 115, 22, 29] };
pub const MFPROTECTIONATTRIBUTE_FAIL_OVER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2234952645,
    data2: 14577,
    data3: 16721,
    data4: [156, 206, 245, 93, 148, 18, 41, 172],
};
pub const MFPROTECTIONATTRIBUTE_HDCP_SRM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1865425159, data2: 13431, data3: 17512, data4: [138, 8, 238, 249, 219, 16, 226, 15] };
pub const MFPROTECTION_ACP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3288142278, data2: 63671, data3: 19744, data4: [176, 8, 29, 177, 125, 97, 242, 218] };
pub const MFPROTECTION_CGMSA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3850267113, data2: 8811, data3: 19761, data4: [180, 227, 211, 219, 0, 135, 54, 221] };
pub const MFPROTECTION_CONSTRICTAUDIO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4291402564,
    data2: 57160,
    data3: 19990,
    data4: [142, 102, 9, 104, 146, 193, 87, 138],
};
pub const MFPROTECTION_CONSTRICTVIDEO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 422801614, data2: 50660, data3: 19514, data4: [138, 102, 105, 89, 180, 218, 68, 66] };
pub const MFPROTECTION_CONSTRICTVIDEO_NOOPM: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2776688845,
    data2: 49735,
    data3: 18775,
    data4: [185, 131, 60, 46, 235, 209, 255, 89],
};
pub const MFPROTECTION_DISABLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2361841691, data2: 65222, data3: 19855, data4: [150, 75, 207, 186, 11, 13, 173, 13] };
pub const MFPROTECTION_DISABLE_SCREEN_SCRAPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2719054244,
    data2: 47053,
    data3: 16600,
    data4: [150, 20, 142, 242, 55, 27, 167, 141],
};
pub const MFPROTECTION_FFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1177179826,
    data2: 10342,
    data3: 19382,
    data4: [152, 13, 109, 141, 158, 219, 26, 140],
};
pub const MFPROTECTION_GRAPHICS_TRANSFER_AES_ENCRYPTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3363036772,
    data2: 55461,
    data3: 18918,
    data4: [136, 187, 251, 150, 63, 211, 212, 206],
};
pub const MFPROTECTION_HARDWARE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1323823297,
    data2: 40663,
    data3: 16975,
    data4: [182, 190, 153, 107, 51, 82, 136, 86],
};
pub const MFPROTECTION_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2927411261,
    data2: 51240,
    data3: 16417,
    data4: [172, 183, 213, 120, 210, 122, 175, 19],
};
pub const MFPROTECTION_HDCP_WITH_TYPE_ENFORCEMENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2762311144, data2: 60768, data3: 17453, data4: [129, 77, 219, 77, 66, 32, 160, 109] };
pub const MFPROTECTION_PROTECTED_SURFACE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1331533158,
    data2: 59202,
    data3: 18981,
    data4: [141, 31, 210, 135, 181, 250, 10, 222],
};
pub const MFPROTECTION_TRUSTEDAUDIODRIVERS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1706947538, data2: 360, data3: 18454, data4: [165, 51, 85, 212, 123, 2, 113, 1] };
pub const MFPROTECTION_VIDEO_FRAMES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 916823228,
    data2: 29697,
    data3: 19084,
    data4: [188, 32, 70, 167, 201, 229, 151, 240],
};
pub const MFPROTECTION_WMDRMOTA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2724701857, data2: 13870, data3: 18384, data4: [136, 5, 70, 40, 89, 138, 35, 228] };
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_UI_Shell_PropertiesSystem"))]
pub struct MFP_ACQUIRE_USER_CREDENTIAL_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub dwUserData: usize,
    pub fProceedWithAuthentication: super::super::Foundation::BOOL,
    pub hrAuthenticationStatus: ::windows_sys::core::HRESULT,
    pub pwszURL: super::super::Foundation::PWSTR,
    pub pwszSite: super::super::Foundation::PWSTR,
    pub pwszRealm: super::super::Foundation::PWSTR,
    pub pwszPackage: super::super::Foundation::PWSTR,
    pub nRetries: i32,
    pub flags: u32,
    pub pCredential: IMFNetCredential,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_UI_Shell_PropertiesSystem"))]
impl ::core::marker::Copy for MFP_ACQUIRE_USER_CREDENTIAL_EVENT {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_UI_Shell_PropertiesSystem"))]
impl ::core::clone::Clone for MFP_ACQUIRE_USER_CREDENTIAL_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFP_CREATION_OPTIONS = i32;
pub const MFP_OPTION_NONE: MFP_CREATION_OPTIONS = 0i32;
pub const MFP_OPTION_FREE_THREADED_CALLBACK: MFP_CREATION_OPTIONS = 1i32;
pub const MFP_OPTION_NO_MMCSS: MFP_CREATION_OPTIONS = 2i32;
pub const MFP_OPTION_NO_REMOTE_DESKTOP_OPTIMIZATION: MFP_CREATION_OPTIONS = 4i32;
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_ERROR_EVENT {
    pub header: MFP_EVENT_HEADER,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_ERROR_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_ERROR_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_EVENT_HEADER {
    pub eEventType: MFP_EVENT_TYPE,
    pub hrEvent: ::windows_sys::core::HRESULT,
    pub pMediaPlayer: IMFPMediaPlayer,
    pub eState: MFP_MEDIAPLAYER_STATE,
    pub pPropertyStore: super::super::UI::Shell::PropertiesSystem::IPropertyStore,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_EVENT_HEADER {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_EVENT_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFP_EVENT_TYPE = i32;
pub const MFP_EVENT_TYPE_PLAY: MFP_EVENT_TYPE = 0i32;
pub const MFP_EVENT_TYPE_PAUSE: MFP_EVENT_TYPE = 1i32;
pub const MFP_EVENT_TYPE_STOP: MFP_EVENT_TYPE = 2i32;
pub const MFP_EVENT_TYPE_POSITION_SET: MFP_EVENT_TYPE = 3i32;
pub const MFP_EVENT_TYPE_RATE_SET: MFP_EVENT_TYPE = 4i32;
pub const MFP_EVENT_TYPE_MEDIAITEM_CREATED: MFP_EVENT_TYPE = 5i32;
pub const MFP_EVENT_TYPE_MEDIAITEM_SET: MFP_EVENT_TYPE = 6i32;
pub const MFP_EVENT_TYPE_FRAME_STEP: MFP_EVENT_TYPE = 7i32;
pub const MFP_EVENT_TYPE_MEDIAITEM_CLEARED: MFP_EVENT_TYPE = 8i32;
pub const MFP_EVENT_TYPE_MF: MFP_EVENT_TYPE = 9i32;
pub const MFP_EVENT_TYPE_ERROR: MFP_EVENT_TYPE = 10i32;
pub const MFP_EVENT_TYPE_PLAYBACK_ENDED: MFP_EVENT_TYPE = 11i32;
pub const MFP_EVENT_TYPE_ACQUIRE_USER_CREDENTIAL: MFP_EVENT_TYPE = 12i32;
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_FRAME_STEP_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_FRAME_STEP_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_FRAME_STEP_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_MEDIAITEM_CLEARED_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_MEDIAITEM_CLEARED_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_MEDIAITEM_CLEARED_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_MEDIAITEM_CREATED_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
    pub dwUserData: usize,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_MEDIAITEM_CREATED_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_MEDIAITEM_CREATED_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_MEDIAITEM_SET_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_MEDIAITEM_SET_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_MEDIAITEM_SET_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFP_MEDIAPLAYER_STATE = i32;
pub const MFP_MEDIAPLAYER_STATE_EMPTY: MFP_MEDIAPLAYER_STATE = 0i32;
pub const MFP_MEDIAPLAYER_STATE_STOPPED: MFP_MEDIAPLAYER_STATE = 1i32;
pub const MFP_MEDIAPLAYER_STATE_PLAYING: MFP_MEDIAPLAYER_STATE = 2i32;
pub const MFP_MEDIAPLAYER_STATE_PAUSED: MFP_MEDIAPLAYER_STATE = 3i32;
pub const MFP_MEDIAPLAYER_STATE_SHUTDOWN: MFP_MEDIAPLAYER_STATE = 4i32;
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_MF_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub MFEventType: u32,
    pub pMFMediaEvent: IMFMediaEvent,
    pub pMediaItem: IMFPMediaItem,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_MF_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_MF_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_PAUSE_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_PAUSE_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_PAUSE_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_PLAYBACK_ENDED_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_PLAYBACK_ENDED_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_PLAYBACK_ENDED_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_PLAY_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_PLAY_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_PLAY_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFP_POSITIONTYPE_100NS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 0, data2: 0, data3: 0, data4: [0, 0, 0, 0, 0, 0, 0, 0] };
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_POSITION_SET_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_POSITION_SET_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_POSITION_SET_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_RATE_SET_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
    pub flRate: f32,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_RATE_SET_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_RATE_SET_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
pub struct MFP_STOP_EVENT {
    pub header: MFP_EVENT_HEADER,
    pub pMediaItem: IMFPMediaItem,
}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::marker::Copy for MFP_STOP_EVENT {}
#[cfg(feature = "Win32_UI_Shell_PropertiesSystem")]
impl ::core::clone::Clone for MFP_STOP_EVENT {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union MFPaletteEntry {
    pub ARGB: MFARGB,
    pub AYCbCr: MFAYUVSample,
}
impl ::core::marker::Copy for MFPaletteEntry {}
impl ::core::clone::Clone for MFPaletteEntry {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFPinholeCameraIntrinsic_IntrinsicModel {
    pub Width: u32,
    pub Height: u32,
    pub CameraModel: MFCameraIntrinsic_PinholeCameraModel,
    pub DistortionModel: MFCameraIntrinsic_DistortionModel,
}
impl ::core::marker::Copy for MFPinholeCameraIntrinsic_IntrinsicModel {}
impl ::core::clone::Clone for MFPinholeCameraIntrinsic_IntrinsicModel {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFPinholeCameraIntrinsics {
    pub IntrinsicModelCount: u32,
    pub IntrinsicModels: [MFPinholeCameraIntrinsic_IntrinsicModel; 1],
}
impl ::core::marker::Copy for MFPinholeCameraIntrinsics {}
impl ::core::clone::Clone for MFPinholeCameraIntrinsics {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFRATE_DIRECTION = i32;
pub const MFRATE_FORWARD: MFRATE_DIRECTION = 0i32;
pub const MFRATE_REVERSE: MFRATE_DIRECTION = 1i32;
#[repr(C)]
pub struct MFRR_COMPONENTS {
    pub dwRRInfoVersion: u32,
    pub dwRRComponents: u32,
    pub pRRComponents: *mut MFRR_COMPONENT_HASH_INFO,
}
impl ::core::marker::Copy for MFRR_COMPONENTS {}
impl ::core::clone::Clone for MFRR_COMPONENTS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFRR_COMPONENT_HASH_INFO {
    pub ulReason: u32,
    pub rgHeaderHash: [u16; 43],
    pub rgPublicKeyHash: [u16; 43],
    pub wszName: [u16; 260],
}
impl ::core::marker::Copy for MFRR_COMPONENT_HASH_INFO {}
impl ::core::clone::Clone for MFRR_COMPONENT_HASH_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFRR_INFO_VERSION: u32 = 0u32;
#[repr(C)]
pub struct MFRatio {
    pub Numerator: u32,
    pub Denominator: u32,
}
impl ::core::marker::Copy for MFRatio {}
impl ::core::clone::Clone for MFRatio {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFSEQUENCER_INVALID_ELEMENT_ID: u32 = 4294967295u32;
pub const MFSESSIONCAP_DOES_NOT_USE_NETWORK: u32 = 64u32;
pub const MFSESSIONCAP_PAUSE: u32 = 4u32;
pub const MFSESSIONCAP_RATE_FORWARD: u32 = 16u32;
pub const MFSESSIONCAP_RATE_REVERSE: u32 = 32u32;
pub const MFSESSIONCAP_SEEK: u32 = 2u32;
pub const MFSESSIONCAP_START: u32 = 1u32;
pub type MFSESSION_GETFULLTOPOLOGY_FLAGS = i32;
pub const MFSESSION_GETFULLTOPOLOGY_CURRENT: MFSESSION_GETFULLTOPOLOGY_FLAGS = 1i32;
pub type MFSESSION_SETTOPOLOGY_FLAGS = i32;
pub const MFSESSION_SETTOPOLOGY_IMMEDIATE: MFSESSION_SETTOPOLOGY_FLAGS = 1i32;
pub const MFSESSION_SETTOPOLOGY_NORESOLUTION: MFSESSION_SETTOPOLOGY_FLAGS = 2i32;
pub const MFSESSION_SETTOPOLOGY_CLEAR_CURRENT: MFSESSION_SETTOPOLOGY_FLAGS = 4i32;
pub type MFSHUTDOWN_STATUS = i32;
pub const MFSHUTDOWN_INITIATED: MFSHUTDOWN_STATUS = 0i32;
pub const MFSHUTDOWN_COMPLETED: MFSHUTDOWN_STATUS = 1i32;
pub type MFSINK_WMDRMACTION = i32;
pub const MFSINK_WMDRMACTION_UNDEFINED: MFSINK_WMDRMACTION = 0i32;
pub const MFSINK_WMDRMACTION_ENCODE: MFSINK_WMDRMACTION = 1i32;
pub const MFSINK_WMDRMACTION_TRANSCODE: MFSINK_WMDRMACTION = 2i32;
pub const MFSINK_WMDRMACTION_TRANSCRYPT: MFSINK_WMDRMACTION = 3i32;
pub const MFSINK_WMDRMACTION_LAST: MFSINK_WMDRMACTION = 3i32;
pub const MFSTARTUP_FULL: u32 = 0u32;
pub const MFSTARTUP_LITE: u32 = 1u32;
pub const MFSTARTUP_NOSOCKET: u32 = 1u32;
pub type MFSTREAMSINK_MARKER_TYPE = i32;
pub const MFSTREAMSINK_MARKER_DEFAULT: MFSTREAMSINK_MARKER_TYPE = 0i32;
pub const MFSTREAMSINK_MARKER_ENDOFSEGMENT: MFSTREAMSINK_MARKER_TYPE = 1i32;
pub const MFSTREAMSINK_MARKER_TICK: MFSTREAMSINK_MARKER_TYPE = 2i32;
pub const MFSTREAMSINK_MARKER_EVENT: MFSTREAMSINK_MARKER_TYPE = 3i32;
pub type MFSampleAllocatorUsage = i32;
pub const MFSampleAllocatorUsage_UsesProvidedAllocator: MFSampleAllocatorUsage = 0i32;
pub const MFSampleAllocatorUsage_UsesCustomAllocator: MFSampleAllocatorUsage = 1i32;
pub const MFSampleAllocatorUsage_DoesNotAllocate: MFSampleAllocatorUsage = 2i32;
pub type MFSampleEncryptionProtectionScheme = i32;
pub const MF_SAMPLE_ENCRYPTION_PROTECTION_SCHEME_NONE: MFSampleEncryptionProtectionScheme = 0i32;
pub const MF_SAMPLE_ENCRYPTION_PROTECTION_SCHEME_AES_CTR: MFSampleEncryptionProtectionScheme = 1i32;
pub const MF_SAMPLE_ENCRYPTION_PROTECTION_SCHEME_AES_CBC: MFSampleEncryptionProtectionScheme = 2i32;
pub const MFSampleExtension_3DVideo: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4168062884, data2: 56660, data3: 20014, data4: [154, 94, 85, 252, 45, 116, 160, 5] };
pub const MFSampleExtension_3DVideo_SampleFormat: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 140973938, data2: 58223, data3: 19711, data4: [151, 179, 215, 46, 32, 152, 122, 72] };
pub const MFSampleExtension_AccumulatedNonRefPicPercent: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2045408479,
    data2: 42816,
    data3: 17499,
    data4: [188, 152, 201, 237, 31, 38, 14, 238],
};
pub const MFSampleExtension_BottomFieldFirst: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2484920483, data2: 27363, data3: 19930, data4: [154, 8, 166, 66, 152, 52, 6, 23] };
pub const MFSampleExtension_CameraExtrinsics: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1802901080,
    data2: 47084,
    data3: 19515,
    data4: [130, 37, 134, 35, 202, 190, 195, 29],
};
pub const MFSampleExtension_CaptureMetadata: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 784212904, data2: 64245, data3: 17482, data4: [166, 162, 235, 129, 8, 128, 171, 93] };
pub const MFSampleExtension_ChromaOnly: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 515446684, data2: 40991, data3: 18501, data4: [140, 4, 14, 101, 162, 110, 176, 79] };
pub const MFSampleExtension_CleanPoint: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2631860696,
    data2: 41200,
    data3: 17338,
    data4: [176, 119, 234, 160, 108, 189, 114, 138],
};
pub const MFSampleExtension_ClosedCaption_CEA708: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 653299816, data2: 59204, data3: 18396, data4: [170, 3, 219, 242, 4, 3, 189, 230] };
pub const MFSampleExtension_ClosedCaption_CEA708_MAX_SIZE: u32 = 256u32;
pub const MFSampleExtension_Content_KeyID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3334993328,
    data2: 44234,
    data3: 16731,
    data4: [135, 217, 16, 68, 20, 105, 239, 198],
};
pub const MFSampleExtension_DecodeTimestamp: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1940477140,
    data2: 2530,
    data3: 18529,
    data4: [190, 252, 148, 189, 151, 192, 142, 110],
};
pub const MFSampleExtension_Depth_MaxReliableDepth: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3830793681, data2: 7951, data3: 18994, data4: [168, 167, 97, 1, 162, 78, 168, 190] };
pub const MFSampleExtension_Depth_MinReliableDepth: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1602585266,
    data2: 58219,
    data3: 18376,
    data4: [155, 135, 254, 225, 202, 114, 197, 176],
};
pub const MFSampleExtension_DerivedFromTopField: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1750222426, data2: 44572, data3: 17747, data4: [142, 155, 195, 66, 15, 203, 22, 55] };
pub const MFSampleExtension_DescrambleData: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1128807398, data2: 18691, data3: 17172, data4: [176, 50, 41, 81, 54, 89, 54, 252] };
pub const MFSampleExtension_DeviceReferenceSystemTime: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1696823130,
    data2: 47661,
    data3: 16479,
    data4: [178, 197, 1, 255, 136, 226, 232, 246],
};
pub const MFSampleExtension_DeviceTimestamp: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2403218919, data2: 11725, data3: 18567, data4: [134, 34, 42, 88, 186, 166, 82, 176] };
pub const MFSampleExtension_DirtyRects: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2611413541,
    data2: 45890,
    data3: 20119,
    data4: [145, 38, 11, 86, 106, 183, 234, 126],
};
pub const MFSampleExtension_Discontinuity: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2631860697,
    data2: 41200,
    data3: 17338,
    data4: [176, 119, 234, 160, 108, 189, 114, 138],
};
pub const MFSampleExtension_Encryption_ClearSliceHeaderData: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1426695412,
    data2: 12813,
    data3: 20076,
    data4: [141, 26, 148, 198, 109, 210, 12, 176],
};
pub const MFSampleExtension_Encryption_CryptByteBlock: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2642684059, data2: 3199, data3: 18195, data4: [171, 149, 16, 138, 180, 42, 216, 1] };
pub const MFSampleExtension_Encryption_HardwareProtection: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2586520875,
    data2: 33392,
    data3: 17379,
    data4: [132, 72, 153, 79, 66, 110, 136, 134],
};
pub const MFSampleExtension_Encryption_HardwareProtection_KeyInfo: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2989957248,
    data2: 17755,
    data3: 19927,
    data4: [153, 137, 26, 149, 87, 132, 183, 84],
};
pub const MFSampleExtension_Encryption_HardwareProtection_KeyInfoID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2361380075,
    data2: 38053,
    data3: 19937,
    data4: [130, 49, 168, 94, 71, 207, 129, 231],
};
pub const MFSampleExtension_Encryption_HardwareProtection_VideoDecryptorContext: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1765044424, data2: 59447, data3: 18336, data4: [136, 203, 83, 91, 144, 94, 53, 130] };
pub const MFSampleExtension_Encryption_KeyID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1983341969,
    data2: 31071,
    data3: 19873,
    data4: [134, 237, 157, 70, 236, 161, 9, 169],
};
pub const MFSampleExtension_Encryption_NALUTypes: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2968545223, data2: 29004, data3: 16748, data4: [141, 89, 95, 77, 223, 137, 19, 182] };
pub const MFSampleExtension_Encryption_Opaque_Data: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 575502309, data2: 5009, data3: 20475, data4: [159, 65, 180, 50, 246, 140, 97, 29] };
pub const MFSampleExtension_Encryption_ProtectionScheme: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3495219350, data2: 10427, data3: 17882, data4: [135, 236, 116, 243, 81, 135, 20, 6] };
pub const MFSampleExtension_Encryption_ResumeVideoOutput: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2754980773,
    data2: 45022,
    data3: 19701,
    data4: [188, 28, 246, 172, 175, 19, 148, 157],
};
pub const MFSampleExtension_Encryption_SEIData: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1022421362, data2: 17730, data3: 18055, data4: [153, 153, 88, 95, 86, 95, 186, 125] };
pub const MFSampleExtension_Encryption_SPSPPSData: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2933788578, data2: 3596, data3: 17724, data4: [183, 243, 222, 134, 147, 54, 77, 17] };
pub const MFSampleExtension_Encryption_SampleID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1721284686, data2: 2810, data3: 17200, data4: [174, 178, 28, 10, 152, 215, 164, 77] };
pub const MFSampleExtension_Encryption_SkipByteBlock: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 223675720, data2: 33559, data3: 19121, data4: [132, 95, 208, 99, 6, 226, 147, 227] };
pub const MFSampleExtension_Encryption_SubSampleMappingSplit: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4261565625,
    data2: 10917,
    data3: 20188,
    data4: [153, 247, 23, 232, 157, 191, 145, 116],
};
pub const MFSampleExtension_Encryption_SubSample_Mapping: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2219111034, data2: 27041, data3: 18650, data4: [189, 8, 17, 206, 243, 104, 48, 210] };
pub const MFSampleExtension_ExtendedCameraIntrinsics: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1443611813,
    data2: 19936,
    data3: 16659,
    data4: [156, 220, 131, 45, 185, 116, 15, 61],
};
pub const MFSampleExtension_FeatureMap: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2687684965, data2: 18172, data3: 16394, data4: [180, 73, 73, 222, 83, 230, 42, 110] };
pub const MFSampleExtension_ForwardedDecodeUnitType: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 144594887, data2: 18387, data3: 18982, data4: [191, 156, 75, 100, 250, 251, 93, 30] };
pub const MFSampleExtension_ForwardedDecodeUnits: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1112307020,
    data2: 38856,
    data3: 18646,
    data4: [135, 119, 252, 65, 247, 182, 8, 121],
};
pub const MFSampleExtension_FrameCorruption: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3034401420, data2: 3051, data3: 17604, data4: [139, 117, 176, 43, 145, 59, 4, 240] };
pub const MFSampleExtension_GenKeyCtx: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 411115723, data2: 55258, data3: 19289, data4: [155, 62, 146, 82, 253, 55, 48, 28] };
pub const MFSampleExtension_GenKeyFunc: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1142727150,
    data2: 27423,
    data3: 17665,
    data4: [144, 58, 222, 135, 223, 66, 246, 237],
};
pub const MFSampleExtension_HDCP_FrameCounter: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2637732960, data2: 62727, data3: 19110, data4: [164, 10, 113, 2, 122, 2, 243, 222] };
pub const MFSampleExtension_HDCP_OptionalHeader: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2586735504,
    data2: 4639,
    data3: 17759,
    data4: [131, 118, 201, 116, 40, 224, 181, 64],
};
pub const MFSampleExtension_HDCP_StreamID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 394157428, data2: 50032, data3: 19066, data4: [149, 162, 54, 131, 60, 1, 208, 175] };
pub const MFSampleExtension_Interlaced: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2983559946,
    data2: 57016,
    data3: 16611,
    data4: [144, 250, 56, 153, 67, 113, 100, 97],
};
pub const MFSampleExtension_LastSlice: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 727536727,
    data2: 21831,
    data3: 20231,
    data4: [184, 200, 180, 163, 169, 161, 218, 172],
};
pub const MFSampleExtension_LongTermReferenceFrameInfo: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2438230847,
    data2: 57789,
    data3: 16831,
    data4: [129, 211, 252, 217, 24, 247, 19, 50],
};
pub const MFSampleExtension_MDLCacheCookie: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1593846521,
    data2: 55545,
    data3: 16803,
    data4: [182, 195, 162, 173, 67, 246, 71, 173],
};
pub const MFSampleExtension_MULTIPLEXED_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2379083385,
    data2: 27482,
    data3: 19525,
    data4: [141, 185, 32, 179, 149, 240, 47, 207],
};
pub const MFSampleExtension_MaxDecodeFrameSize: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3553387855,
    data2: 63987,
    data3: 18963,
    data4: [136, 159, 240, 78, 178, 181, 185, 87],
};
pub const MFSampleExtension_MeanAbsoluteDifference: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 484171281, data2: 2228, data3: 17169, data4: [166, 221, 15, 159, 55, 25, 7, 170] };
pub const MFSampleExtension_MoveRegions: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3802580627,
    data2: 14987,
    data3: 19341,
    data4: [149, 208, 246, 2, 129, 161, 47, 183],
};
pub const MFSampleExtension_NALULengthInfo: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 420630140, data2: 44363, data3: 18015, data4: [187, 24, 32, 24, 98, 135, 182, 175] };
pub const MFSampleExtension_PacketCrossOffsets: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 663316253,
    data2: 14495,
    data3: 16571,
    data4: [144, 217, 194, 130, 247, 127, 154, 189],
};
pub const MFSampleExtension_PhotoThumbnail: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1958463580,
    data2: 51387,
    data3: 17116,
    data4: [181, 134, 218, 23, 255, 211, 93, 204],
};
pub const MFSampleExtension_PhotoThumbnailMediaType: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1638749216,
    data2: 60408,
    data3: 16707,
    data4: [137, 175, 107, 242, 95, 103, 45, 239],
};
pub const MFSampleExtension_PinholeCameraIntrinsics: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1323546309,
    data2: 27157,
    data3: 20082,
    data4: [151, 97, 112, 193, 219, 139, 159, 227],
};
pub const MFSampleExtension_ROIRectangle: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 873767992, data2: 18840, data3: 19756, data4: [190, 130, 190, 60, 160, 178, 77, 67] };
pub const MFSampleExtension_RepeatFirstField: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 810362236,
    data2: 29843,
    data3: 20413,
    data4: [177, 73, 146, 40, 222, 141, 154, 153],
};
pub const MFSampleExtension_RepeatFrame: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2294182799, data2: 1809, data3: 20290, data4: [180, 88, 52, 74, 237, 66, 236, 47] };
pub const MFSampleExtension_SampleKeyID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2664895432,
    data2: 39815,
    data3: 19238,
    data4: [130, 151, 169, 59, 12, 90, 138, 204],
};
pub const MFSampleExtension_SingleField: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2642802710,
    data2: 25995,
    data3: 17754,
    data4: [189, 224, 159, 167, 225, 90, 184, 249],
};
pub const MFSampleExtension_Spatial_CameraCoordinateSystem: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2635319343, data2: 8601, data3: 20071, data4: [145, 205, 209, 164, 24, 31, 37, 52] };
pub const MFSampleExtension_Spatial_CameraProjectionTransform: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1207565493,
    data2: 10754,
    data3: 20262,
    data4: [164, 119, 121, 47, 223, 149, 136, 106],
};
pub const MFSampleExtension_Spatial_CameraViewTransform: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1311055780,
    data2: 33551,
    data3: 18288,
    data4: [133, 154, 75, 141, 153, 170, 128, 155],
};
pub const MFSampleExtension_TargetGlobalLuminance: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1063317302, data2: 12783, data3: 19887, data4: [131, 96, 148, 3, 151, 228, 30, 243] };
pub const MFSampleExtension_Timestamp: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 507734425, data2: 27070, data3: 19578, data4: [147, 105, 112, 6, 140, 2, 96, 203] };
pub const MFSampleExtension_Token: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2190793318, data2: 62248, data3: 18437, data4: [181, 81, 0, 222, 180, 197, 122, 97] };
pub const MFSampleExtension_VideoDSPMode: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3240973771,
    data2: 55257,
    data3: 18285,
    data4: [129, 243, 105, 17, 127, 22, 62, 160],
};
pub const MFSampleExtension_VideoEncodePictureType: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2536965350, data2: 52500, data3: 18492, data4: [143, 32, 201, 252, 9, 40, 186, 213] };
pub const MFSampleExtension_VideoEncodeQP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3002066040, data2: 63865, data3: 19558, data4: [185, 94, 238, 43, 130, 200, 47, 54] };
pub type MFSensorDeviceMode = i32;
pub const MFSensorDeviceMode_Controller: MFSensorDeviceMode = 0i32;
pub const MFSensorDeviceMode_Shared: MFSensorDeviceMode = 1i32;
pub type MFSensorDeviceType = i32;
pub const MFSensorDeviceType_Unknown: MFSensorDeviceType = 0i32;
pub const MFSensorDeviceType_Device: MFSensorDeviceType = 1i32;
pub const MFSensorDeviceType_MediaSource: MFSensorDeviceType = 2i32;
pub const MFSensorDeviceType_FrameProvider: MFSensorDeviceType = 3i32;
pub const MFSensorDeviceType_SensorTransform: MFSensorDeviceType = 4i32;
pub type MFSensorStreamType = i32;
pub const MFSensorStreamType_Unknown: MFSensorStreamType = 0i32;
pub const MFSensorStreamType_Input: MFSensorStreamType = 1i32;
pub const MFSensorStreamType_Output: MFSensorStreamType = 2i32;
pub type MFSequencerTopologyFlags = i32;
pub const SequencerTopologyFlags_Last: MFSequencerTopologyFlags = 1i32;
pub type MFStandardVideoFormat = i32;
pub const MFStdVideoFormat_reserved: MFStandardVideoFormat = 0i32;
pub const MFStdVideoFormat_NTSC: MFStandardVideoFormat = 1i32;
pub const MFStdVideoFormat_PAL: MFStandardVideoFormat = 2i32;
pub const MFStdVideoFormat_DVD_NTSC: MFStandardVideoFormat = 3i32;
pub const MFStdVideoFormat_DVD_PAL: MFStandardVideoFormat = 4i32;
pub const MFStdVideoFormat_DV_PAL: MFStandardVideoFormat = 5i32;
pub const MFStdVideoFormat_DV_NTSC: MFStandardVideoFormat = 6i32;
pub const MFStdVideoFormat_ATSC_SD480i: MFStandardVideoFormat = 7i32;
pub const MFStdVideoFormat_ATSC_HD1080i: MFStandardVideoFormat = 8i32;
pub const MFStdVideoFormat_ATSC_HD720p: MFStandardVideoFormat = 9i32;
pub const MFStreamExtension_CameraExtrinsics: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1751226064, data2: 5090, data3: 16857, data4: [150, 56, 239, 3, 44, 39, 42, 82] };
pub const MFStreamExtension_ExtendedCameraIntrinsics: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2859774943,
    data2: 39468,
    data3: 18646,
    data4: [131, 147, 91, 209, 193, 168, 30, 110],
};
pub const MFStreamExtension_PinholeCameraIntrinsics: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3685483605, data2: 3784, data3: 19183, data4: [156, 50, 122, 62, 227, 69, 111, 83] };
pub const MFStreamFormat_MPEG2Program: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 640706513,
    data2: 54064,
    data3: 17884,
    data4: [182, 105, 52, 217, 134, 228, 227, 225],
};
pub const MFStreamFormat_MPEG2Transport: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3765272611, data2: 56134, data3: 4559, data4: [180, 209, 0, 128, 95, 108, 187, 234] };
pub const MFSubtitleFormat_ATSC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2141715107,
    data2: 65198,
    data3: 19990,
    data4: [174, 223, 54, 185, 172, 251, 176, 153],
};
pub const MFSubtitleFormat_CustomUserData: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 464771145,
    data2: 26132,
    data3: 19840,
    data4: [136, 130, 237, 36, 170, 130, 218, 146],
};
pub const MFSubtitleFormat_PGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1911819850, data2: 4728, data3: 17474, data4: [179, 13, 57, 221, 29, 119, 34, 188] };
pub const MFSubtitleFormat_SRT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1581678382,
    data2: 30666,
    data3: 19621,
    data4: [131, 145, 209, 66, 237, 75, 118, 200],
};
pub const MFSubtitleFormat_SSA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1461152283, data2: 6814, data3: 20202, data4: [171, 239, 198, 23, 96, 25, 138, 196] };
pub const MFSubtitleFormat_TTML: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1944533394, data2: 39440, data3: 17238, data4: [149, 87, 113, 148, 233, 30, 62, 84] };
pub const MFSubtitleFormat_VobSub: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1804484852, data2: 36140, data3: 19693, data4: [173, 145, 89, 96, 228, 91, 68, 51] };
pub const MFSubtitleFormat_WebVTT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3364278805,
    data2: 62597,
    data3: 16571,
    data4: [141, 182, 250, 219, 198, 25, 164, 93],
};
pub const MFSubtitleFormat_XML: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 537327951, data2: 10698, data3: 16789, data4: [184, 219, 0, 222, 216, 255, 12, 151] };
pub type MFTIMER_FLAGS = i32;
pub const MFTIMER_RELATIVE: MFTIMER_FLAGS = 1i32;
pub type MFTOPOLOGY_DXVA_MODE = i32;
pub const MFTOPOLOGY_DXVA_DEFAULT: MFTOPOLOGY_DXVA_MODE = 0i32;
pub const MFTOPOLOGY_DXVA_NONE: MFTOPOLOGY_DXVA_MODE = 1i32;
pub const MFTOPOLOGY_DXVA_FULL: MFTOPOLOGY_DXVA_MODE = 2i32;
pub type MFTOPOLOGY_HARDWARE_MODE = i32;
pub const MFTOPOLOGY_HWMODE_SOFTWARE_ONLY: MFTOPOLOGY_HARDWARE_MODE = 0i32;
pub const MFTOPOLOGY_HWMODE_USE_HARDWARE: MFTOPOLOGY_HARDWARE_MODE = 1i32;
pub const MFTOPOLOGY_HWMODE_USE_ONLY_HARDWARE: MFTOPOLOGY_HARDWARE_MODE = 2i32;
#[repr(C)]
pub struct MFTOPONODE_ATTRIBUTE_UPDATE {
    pub NodeId: u64,
    pub guidAttributeKey: ::windows_sys::core::GUID,
    pub attrType: MF_ATTRIBUTE_TYPE,
    pub Anonymous: MFTOPONODE_ATTRIBUTE_UPDATE_0,
}
impl ::core::marker::Copy for MFTOPONODE_ATTRIBUTE_UPDATE {}
impl ::core::clone::Clone for MFTOPONODE_ATTRIBUTE_UPDATE {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub union MFTOPONODE_ATTRIBUTE_UPDATE_0 {
    pub u32: u32,
    pub u64: u64,
    pub d: f64,
}
impl ::core::marker::Copy for MFTOPONODE_ATTRIBUTE_UPDATE_0 {}
impl ::core::clone::Clone for MFTOPONODE_ATTRIBUTE_UPDATE_0 {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFT_AUDIO_DECODER_AUDIO_ENDPOINT_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3352092014,
    data2: 21400,
    data3: 18069,
    data4: [139, 231, 81, 179, 233, 81, 17, 189],
};
pub const MFT_AUDIO_DECODER_DEGRADATION_INFO_ATTRIBUTE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1815316141,
    data2: 60448,
    data3: 17165,
    data4: [178, 165, 80, 92, 113, 120, 217, 196],
};
pub type MFT_AUDIO_DECODER_DEGRADATION_REASON = i32;
pub const MFT_AUDIO_DECODER_DEGRADATION_REASON_NONE: MFT_AUDIO_DECODER_DEGRADATION_REASON = 0i32;
pub const MFT_AUDIO_DECODER_DEGRADATION_REASON_LICENSING_REQUIREMENT: MFT_AUDIO_DECODER_DEGRADATION_REASON = 1i32;
pub type MFT_AUDIO_DECODER_DEGRADATION_TYPE = i32;
pub const MFT_AUDIO_DECODER_DEGRADATION_TYPE_NONE: MFT_AUDIO_DECODER_DEGRADATION_TYPE = 0i32;
pub const MFT_AUDIO_DECODER_DEGRADATION_TYPE_DOWNMIX2CHANNEL: MFT_AUDIO_DECODER_DEGRADATION_TYPE = 1i32;
pub const MFT_AUDIO_DECODER_DEGRADATION_TYPE_DOWNMIX6CHANNEL: MFT_AUDIO_DECODER_DEGRADATION_TYPE = 2i32;
pub const MFT_AUDIO_DECODER_DEGRADATION_TYPE_DOWNMIX8CHANNEL: MFT_AUDIO_DECODER_DEGRADATION_TYPE = 3i32;
pub const MFT_AUDIO_DECODER_SPATIAL_METADATA_CLIENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 93879796, data2: 4720, data3: 18841, data4: [146, 95, 142, 147, 154, 124, 10, 247] };
pub const MFT_CATEGORY_AUDIO_DECODER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2661760948, data2: 61306, data3: 17753, data4: [141, 93, 113, 157, 143, 4, 38, 199] };
pub const MFT_CATEGORY_AUDIO_EFFECT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 285625416, data2: 13896, data3: 20176, data4: [147, 46, 5, 206, 138, 200, 17, 183] };
pub const MFT_CATEGORY_AUDIO_ENCODER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2445691856,
    data2: 63774,
    data3: 19852,
    data4: [146, 118, 219, 36, 130, 121, 217, 117],
};
pub const MFT_CATEGORY_DEMULTIPLEXER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2825915002,
    data2: 37787,
    data3: 17605,
    data4: [153, 215, 118, 34, 107, 35, 179, 241],
};
pub const MFT_CATEGORY_ENCRYPTOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2965800894, data2: 461, data3: 17589, data4: [184, 178, 124, 29, 126, 5, 139, 31] };
pub const MFT_CATEGORY_MULTIPLEXER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 94131742, data2: 1454, data3: 19297, data4: [182, 157, 85, 182, 30, 229, 74, 123] };
pub const MFT_CATEGORY_OTHER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2417450327,
    data2: 47082,
    data3: 18689,
    data4: [174, 179, 147, 58, 135, 71, 117, 111],
};
pub const MFT_CATEGORY_VIDEO_DECODER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3602918731, data2: 26675, data3: 17844, data4: [151, 26, 5, 164, 176, 75, 171, 145] };
pub const MFT_CATEGORY_VIDEO_EFFECT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 316767265, data2: 21292, data3: 19054, data4: [138, 28, 64, 130, 90, 115, 99, 151] };
pub const MFT_CATEGORY_VIDEO_ENCODER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4154371197,
    data2: 58693,
    data3: 17287,
    data4: [189, 238, 214, 71, 215, 189, 228, 42],
};
pub const MFT_CATEGORY_VIDEO_PROCESSOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808363004, data2: 43615, data3: 18425, data4: [159, 122, 194, 24, 139, 177, 99, 2] };
pub const MFT_CATEGORY_VIDEO_RENDERER_EFFECT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 341629108,
    data2: 37620,
    data3: 19235,
    data4: [138, 231, 224, 223, 6, 194, 218, 149],
};
pub const MFT_CODEC_MERIT_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2292697877, data2: 31495, data3: 18996, data4: [145, 40, 230, 76, 103, 3, 196, 211] };
pub const MFT_CONNECTED_STREAM_ATTRIBUTE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1911470112,
    data2: 42399,
    data3: 19938,
    data4: [188, 236, 56, 219, 29, 214, 17, 164],
};
pub const MFT_CONNECTED_TO_HW_STREAM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 887547688, data2: 1750, data3: 17553, data4: [165, 83, 71, 149, 101, 13, 185, 18] };
pub const MFT_DECODER_EXPOSE_OUTPUT_TYPES_IN_NATIVE_ORDER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4018176831, data2: 63738, data3: 17625, data4: [128, 216, 65, 237, 98, 50, 103, 12] };
pub const MFT_DECODER_FINAL_VIDEO_RESOLUTION_HINT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3694101654, data2: 5572, data3: 16506, data4: [182, 240, 27, 102, 171, 95, 191, 83] };
pub const MFT_DECODER_QUALITY_MANAGEMENT_CUSTOM_CONTROL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2723033303, data2: 56869, data3: 17752, data4: [187, 251, 113, 7, 10, 45, 51, 46] };
pub const MFT_DECODER_QUALITY_MANAGEMENT_RECOVERY_WITHOUT_ARTIFACTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3633843691, data2: 2632, data3: 16991, data4: [134, 35, 97, 29, 180, 29, 56, 16] };
pub type MFT_DRAIN_TYPE = i32;
pub const MFT_DRAIN_PRODUCE_TAILS: MFT_DRAIN_TYPE = 0i32;
pub const MFT_DRAIN_NO_TAILS: MFT_DRAIN_TYPE = 1i32;
pub const MFT_ENCODER_ERROR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3369201060, data2: 39140, data3: 16853, data4: [146, 151, 68, 245, 56, 82, 249, 14] };
pub const MFT_ENCODER_SUPPORTS_CONFIG_EVENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2258851246, data2: 14967, data3: 20164, data4: [159, 49, 1, 20, 154, 78, 146, 222] };
pub const MFT_END_STREAMING_AWARE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1895548997, data2: 45182, data3: 16521, data4: [176, 100, 57, 157, 198, 17, 15, 41] };
pub const MFT_ENUM_ADAPTER_LUID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 490295692, data2: 57888, data3: 19880, data4: [160, 127, 186, 23, 37, 82, 214, 177] };
pub const MFT_ENUM_HARDWARE_URL_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 800614060, data2: 45176, data3: 18754, data4: [171, 108, 0, 61, 5, 205, 166, 116] };
pub const MFT_ENUM_HARDWARE_VENDOR_ID_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 988590284, data2: 859, data3: 19404, data4: [129, 133, 43, 141, 85, 30, 243, 175] };
pub const MFT_ENUM_TRANSCODE_ONLY_ATTRIBUTE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 287221965,
    data2: 46634,
    data3: 19419,
    data4: [137, 246, 103, 255, 205, 194, 69, 139],
};
pub const MFT_ENUM_VIDEO_RENDERER_EXTENSION_PROFILE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1657104680, data2: 39502, data3: 17467, data4: [185, 220, 202, 200, 48, 194, 65, 0] };
pub const MFT_FIELDOFUSE_UNLOCK_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2395138557, data2: 37192, data3: 16653, data4: [131, 30, 112, 36, 57, 70, 26, 142] };
pub const MFT_FRIENDLY_NAME_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 827325358, data2: 23361, data3: 19605, data4: [156, 25, 78, 125, 88, 111, 172, 227] };
pub const MFT_GFX_DRIVER_VERSION_ID_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4081815699, data2: 1504, data3: 19222, data4: [153, 61, 62, 42, 44, 222, 106, 211] };
pub const MFT_HW_TIMESTAMP_WITH_QPC_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2365788088,
    data2: 52291,
    data3: 16984,
    data4: [162, 46, 146, 16, 190, 248, 155, 228],
};
#[repr(C)]
pub struct MFT_INPUT_STREAM_INFO {
    pub hnsMaxLatency: i64,
    pub dwFlags: u32,
    pub cbSize: u32,
    pub cbMaxLookahead: u32,
    pub cbAlignment: u32,
}
impl ::core::marker::Copy for MFT_INPUT_STREAM_INFO {}
impl ::core::clone::Clone for MFT_INPUT_STREAM_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFT_INPUT_TYPES_Attributes: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1115081137,
    data2: 30109,
    data3: 19443,
    data4: [156, 208, 13, 114, 61, 19, 143, 150],
};
pub type MFT_MESSAGE_TYPE = i32;
pub const MFT_MESSAGE_COMMAND_FLUSH: MFT_MESSAGE_TYPE = 0i32;
pub const MFT_MESSAGE_COMMAND_DRAIN: MFT_MESSAGE_TYPE = 1i32;
pub const MFT_MESSAGE_SET_D3D_MANAGER: MFT_MESSAGE_TYPE = 2i32;
pub const MFT_MESSAGE_DROP_SAMPLES: MFT_MESSAGE_TYPE = 3i32;
pub const MFT_MESSAGE_COMMAND_TICK: MFT_MESSAGE_TYPE = 4i32;
pub const MFT_MESSAGE_NOTIFY_BEGIN_STREAMING: MFT_MESSAGE_TYPE = 268435456i32;
pub const MFT_MESSAGE_NOTIFY_END_STREAMING: MFT_MESSAGE_TYPE = 268435457i32;
pub const MFT_MESSAGE_NOTIFY_END_OF_STREAM: MFT_MESSAGE_TYPE = 268435458i32;
pub const MFT_MESSAGE_NOTIFY_START_OF_STREAM: MFT_MESSAGE_TYPE = 268435459i32;
pub const MFT_MESSAGE_NOTIFY_RELEASE_RESOURCES: MFT_MESSAGE_TYPE = 268435460i32;
pub const MFT_MESSAGE_NOTIFY_REACQUIRE_RESOURCES: MFT_MESSAGE_TYPE = 268435461i32;
pub const MFT_MESSAGE_NOTIFY_EVENT: MFT_MESSAGE_TYPE = 268435462i32;
pub const MFT_MESSAGE_COMMAND_SET_OUTPUT_STREAM_STATE: MFT_MESSAGE_TYPE = 268435463i32;
pub const MFT_MESSAGE_COMMAND_FLUSH_OUTPUT_STREAM: MFT_MESSAGE_TYPE = 268435464i32;
pub const MFT_MESSAGE_COMMAND_MARKER: MFT_MESSAGE_TYPE = 536870912i32;
pub const MFT_OUTPUT_BOUND_UPPER_UNBOUNDED: u64 = 9223372036854775807u64;
#[repr(C)]
pub struct MFT_OUTPUT_DATA_BUFFER {
    pub dwStreamID: u32,
    pub pSample: IMFSample,
    pub dwStatus: u32,
    pub pEvents: IMFCollection,
}
impl ::core::marker::Copy for MFT_OUTPUT_DATA_BUFFER {}
impl ::core::clone::Clone for MFT_OUTPUT_DATA_BUFFER {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MFT_OUTPUT_STREAM_INFO {
    pub dwFlags: u32,
    pub cbSize: u32,
    pub cbAlignment: u32,
}
impl ::core::marker::Copy for MFT_OUTPUT_STREAM_INFO {}
impl ::core::clone::Clone for MFT_OUTPUT_STREAM_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFT_OUTPUT_TYPES_Attributes: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2393804019, data2: 42063, data3: 17158, data4: [186, 92, 191, 93, 218, 36, 40, 24] };
pub const MFT_POLICY_SET_AWARE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1516452633, data2: 52281, data3: 20392, data4: [140, 165, 89, 152, 27, 122, 0, 24] };
pub const MFT_PREFERRED_ENCODER_PROFILE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1392527625,
    data2: 7925,
    data3: 18135,
    data4: [161, 142, 90, 117, 248, 181, 144, 95],
};
pub const MFT_PREFERRED_OUTPUTTYPE_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2121270425, data2: 14698, data3: 18926, data4: [177, 180, 246, 40, 2, 30, 140, 157] };
pub const MFT_PROCESS_LOCAL_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1412531940,
    data2: 17993,
    data3: 20069,
    data4: [181, 136, 74, 163, 82, 175, 243, 121],
};
#[repr(C)]
pub struct MFT_REGISTER_TYPE_INFO {
    pub guidMajorType: ::windows_sys::core::GUID,
    pub guidSubtype: ::windows_sys::core::GUID,
}
impl ::core::marker::Copy for MFT_REGISTER_TYPE_INFO {}
impl ::core::clone::Clone for MFT_REGISTER_TYPE_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MFT_REGISTRATION_INFO {
    pub clsid: ::windows_sys::core::GUID,
    pub guidCategory: ::windows_sys::core::GUID,
    pub uiFlags: u32,
    pub pszName: super::super::Foundation::PWSTR,
    pub cInTypes: u32,
    pub pInTypes: *mut MFT_REGISTER_TYPE_INFO,
    pub cOutTypes: u32,
    pub pOutTypes: *mut MFT_REGISTER_TYPE_INFO,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MFT_REGISTRATION_INFO {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MFT_REGISTRATION_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFT_REMUX_MARK_I_PICTURE_AS_CLEAN_POINT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 911118213, data2: 16174, data3: 17260, data4: [178, 162, 68, 64, 160, 18, 169, 232] };
pub const MFT_STREAMS_UNLIMITED: u32 = 4294967295u32;
#[repr(C)]
pub struct MFT_STREAM_STATE_PARAM {
    pub StreamId: u32,
    pub State: MF_STREAM_STATE,
}
impl ::core::marker::Copy for MFT_STREAM_STATE_PARAM {}
impl ::core::clone::Clone for MFT_STREAM_STATE_PARAM {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MFT_SUPPORT_3DVIDEO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 155156913, data2: 20270, data3: 17969, data4: [129, 104, 121, 52, 3, 42, 1, 211] };
pub const MFT_SUPPORT_DYNAMIC_FORMAT_CHANGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1397189137, data2: 16147, data3: 18939, data4: [172, 66, 238, 39, 51, 201, 103, 65] };
pub const MFT_TRANSFORM_CLSID_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1747043371,
    data2: 26020,
    data3: 20098,
    data4: [153, 188, 154, 136, 32, 94, 205, 12],
};
pub const MFT_USING_HARDWARE_DRM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 888842109, data2: 55198, data3: 18775, data4: [184, 206, 54, 43, 38, 132, 153, 108] };
pub const MFTranscodeContainerType_3GP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 885326183,
    data2: 17522,
    data3: 20276,
    data4: [158, 160, 196, 159, 186, 207, 3, 125],
};
pub const MFTranscodeContainerType_AC3: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1837994435, data2: 35985, data3: 20177, data4: [135, 66, 140, 52, 125, 91, 68, 208] };
pub const MFTranscodeContainerType_ADTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 321901181, data2: 3842, data3: 17374, data4: [163, 1, 56, 251, 187, 179, 131, 78] };
pub const MFTranscodeContainerType_AMR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 39672531, data2: 25114, data3: 18267, data4: [150, 77, 102, 177, 200, 36, 240, 121] };
pub const MFTranscodeContainerType_ASF: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1125085038,
    data2: 46783,
    data3: 20417,
    data4: [160, 189, 158, 228, 110, 238, 42, 251],
};
pub const MFTranscodeContainerType_AVI: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2128603311,
    data2: 16431,
    data3: 19830,
    data4: [163, 60, 97, 159, 209, 87, 208, 241],
};
pub const MFTranscodeContainerType_FLAC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 825510563, data2: 1449, data3: 17077, data4: [144, 27, 142, 157, 66, 87, 247, 94] };
pub const MFTranscodeContainerType_FMPEG4: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2611508977, data2: 16799, data3: 19319, data4: [161, 224, 53, 149, 157, 157, 64, 4] };
pub const MFTranscodeContainerType_MP3: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3828922642,
    data2: 33777,
    data3: 19942,
    data4: [158, 58, 159, 251, 198, 221, 36, 209],
};
pub const MFTranscodeContainerType_MPEG2: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3217218553,
    data2: 31668,
    data3: 20367,
    data4: [175, 222, 225, 18, 196, 75, 168, 130],
};
pub const MFTranscodeContainerType_MPEG4: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3698118749, data2: 47568, data3: 16623, data4: [189, 53, 250, 98, 44, 26, 178, 138] };
pub const MFTranscodeContainerType_WAVE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1690518844,
    data2: 3878,
    data3: 18241,
    data4: [190, 99, 135, 189, 248, 187, 147, 91],
};
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MFVIDEOFORMAT {
    pub dwSize: u32,
    pub videoInfo: MFVideoInfo,
    pub guidFormat: ::windows_sys::core::GUID,
    pub compressedInfo: MFVideoCompressedInfo,
    pub surfaceInfo: MFVideoSurfaceInfo,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MFVIDEOFORMAT {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MFVIDEOFORMAT {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFVP_MESSAGE_TYPE = i32;
pub const MFVP_MESSAGE_FLUSH: MFVP_MESSAGE_TYPE = 0i32;
pub const MFVP_MESSAGE_INVALIDATEMEDIATYPE: MFVP_MESSAGE_TYPE = 1i32;
pub const MFVP_MESSAGE_PROCESSINPUTNOTIFY: MFVP_MESSAGE_TYPE = 2i32;
pub const MFVP_MESSAGE_BEGINSTREAMING: MFVP_MESSAGE_TYPE = 3i32;
pub const MFVP_MESSAGE_ENDSTREAMING: MFVP_MESSAGE_TYPE = 4i32;
pub const MFVP_MESSAGE_ENDOFSTREAM: MFVP_MESSAGE_TYPE = 5i32;
pub const MFVP_MESSAGE_STEP: MFVP_MESSAGE_TYPE = 6i32;
pub const MFVP_MESSAGE_CANCELSTEP: MFVP_MESSAGE_TYPE = 7i32;
pub type MFVideo3DFormat = i32;
pub const MFVideo3DSampleFormat_BaseView: MFVideo3DFormat = 0i32;
pub const MFVideo3DSampleFormat_MultiView: MFVideo3DFormat = 1i32;
pub const MFVideo3DSampleFormat_Packed_LeftRight: MFVideo3DFormat = 2i32;
pub const MFVideo3DSampleFormat_Packed_TopBottom: MFVideo3DFormat = 3i32;
pub type MFVideo3DSampleFormat = i32;
pub const MFSampleExtension_3DVideo_MultiView: MFVideo3DSampleFormat = 1i32;
pub const MFSampleExtension_3DVideo_Packed: MFVideo3DSampleFormat = 0i32;
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9", feature = "Win32_Graphics_Gdi"))]
pub struct MFVideoAlphaBitmap {
    pub GetBitmapFromDC: super::super::Foundation::BOOL,
    pub bitmap: MFVideoAlphaBitmap_0,
    pub params: MFVideoAlphaBitmapParams,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9", feature = "Win32_Graphics_Gdi"))]
impl ::core::marker::Copy for MFVideoAlphaBitmap {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9", feature = "Win32_Graphics_Gdi"))]
impl ::core::clone::Clone for MFVideoAlphaBitmap {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9", feature = "Win32_Graphics_Gdi"))]
pub union MFVideoAlphaBitmap_0 {
    pub hdc: super::super::Graphics::Gdi::HDC,
    pub pDDS: super::super::Graphics::Direct3D9::IDirect3DSurface9,
}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9", feature = "Win32_Graphics_Gdi"))]
impl ::core::marker::Copy for MFVideoAlphaBitmap_0 {}
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9", feature = "Win32_Graphics_Gdi"))]
impl ::core::clone::Clone for MFVideoAlphaBitmap_0 {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFVideoAlphaBitmapFlags = i32;
pub const MFVideoAlphaBitmap_EntireDDS: MFVideoAlphaBitmapFlags = 1i32;
pub const MFVideoAlphaBitmap_SrcColorKey: MFVideoAlphaBitmapFlags = 2i32;
pub const MFVideoAlphaBitmap_SrcRect: MFVideoAlphaBitmapFlags = 4i32;
pub const MFVideoAlphaBitmap_DestRect: MFVideoAlphaBitmapFlags = 8i32;
pub const MFVideoAlphaBitmap_FilterMode: MFVideoAlphaBitmapFlags = 16i32;
pub const MFVideoAlphaBitmap_Alpha: MFVideoAlphaBitmapFlags = 32i32;
pub const MFVideoAlphaBitmap_BitMask: MFVideoAlphaBitmapFlags = 63i32;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MFVideoAlphaBitmapParams {
    pub dwFlags: u32,
    pub clrSrcKey: u32,
    pub rcSrc: super::super::Foundation::RECT,
    pub nrcDest: MFVideoNormalizedRect,
    pub fAlpha: f32,
    pub dwFilterMode: u32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MFVideoAlphaBitmapParams {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MFVideoAlphaBitmapParams {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MFVideoArea {
    pub OffsetX: MFOffset,
    pub OffsetY: MFOffset,
    pub Area: super::super::Foundation::SIZE,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MFVideoArea {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MFVideoArea {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFVideoAspectRatioMode = i32;
pub const MFVideoARMode_None: MFVideoAspectRatioMode = 0i32;
pub const MFVideoARMode_PreservePicture: MFVideoAspectRatioMode = 1i32;
pub const MFVideoARMode_PreservePixel: MFVideoAspectRatioMode = 2i32;
pub const MFVideoARMode_NonLinearStretch: MFVideoAspectRatioMode = 4i32;
pub const MFVideoARMode_Mask: MFVideoAspectRatioMode = 7i32;
pub type MFVideoChromaSubsampling = i32;
pub const MFVideoChromaSubsampling_Unknown: MFVideoChromaSubsampling = 0i32;
pub const MFVideoChromaSubsampling_ProgressiveChroma: MFVideoChromaSubsampling = 8i32;
pub const MFVideoChromaSubsampling_Horizontally_Cosited: MFVideoChromaSubsampling = 4i32;
pub const MFVideoChromaSubsampling_Vertically_Cosited: MFVideoChromaSubsampling = 2i32;
pub const MFVideoChromaSubsampling_Vertically_AlignedChromaPlanes: MFVideoChromaSubsampling = 1i32;
pub const MFVideoChromaSubsampling_MPEG2: MFVideoChromaSubsampling = 5i32;
pub const MFVideoChromaSubsampling_MPEG1: MFVideoChromaSubsampling = 1i32;
pub const MFVideoChromaSubsampling_DV_PAL: MFVideoChromaSubsampling = 6i32;
pub const MFVideoChromaSubsampling_Cosited: MFVideoChromaSubsampling = 7i32;
pub const MFVideoChromaSubsampling_Last: MFVideoChromaSubsampling = 8i32;
pub const MFVideoChromaSubsampling_ForceDWORD: MFVideoChromaSubsampling = 2147483647i32;
#[repr(C)]
pub struct MFVideoCompressedInfo {
    pub AvgBitrate: i64,
    pub AvgBitErrorRate: i64,
    pub MaxKeyFrameSpacing: u32,
}
impl ::core::marker::Copy for MFVideoCompressedInfo {}
impl ::core::clone::Clone for MFVideoCompressedInfo {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFVideoDRMFlags = i32;
pub const MFVideoDRMFlag_None: MFVideoDRMFlags = 0i32;
pub const MFVideoDRMFlag_AnalogProtected: MFVideoDRMFlags = 1i32;
pub const MFVideoDRMFlag_DigitallyProtected: MFVideoDRMFlags = 2i32;
pub type MFVideoDSPMode = i32;
pub const MFVideoDSPMode_Passthrough: MFVideoDSPMode = 1i32;
pub const MFVideoDSPMode_Stabilization: MFVideoDSPMode = 4i32;
pub type MFVideoFlags = i32;
pub const MFVideoFlag_PAD_TO_Mask: MFVideoFlags = 3i32;
pub const MFVideoFlag_PAD_TO_None: MFVideoFlags = 0i32;
pub const MFVideoFlag_PAD_TO_4x3: MFVideoFlags = 1i32;
pub const MFVideoFlag_PAD_TO_16x9: MFVideoFlags = 2i32;
pub const MFVideoFlag_SrcContentHintMask: MFVideoFlags = 28i32;
pub const MFVideoFlag_SrcContentHintNone: MFVideoFlags = 0i32;
pub const MFVideoFlag_SrcContentHint16x9: MFVideoFlags = 4i32;
pub const MFVideoFlag_SrcContentHint235_1: MFVideoFlags = 8i32;
pub const MFVideoFlag_AnalogProtected: MFVideoFlags = 32i32;
pub const MFVideoFlag_DigitallyProtected: MFVideoFlags = 64i32;
pub const MFVideoFlag_ProgressiveContent: MFVideoFlags = 128i32;
pub const MFVideoFlag_FieldRepeatCountMask: MFVideoFlags = 1792i32;
pub const MFVideoFlag_FieldRepeatCountShift: MFVideoFlags = 8i32;
pub const MFVideoFlag_ProgressiveSeqReset: MFVideoFlags = 2048i32;
pub const MFVideoFlag_PanScanEnabled: MFVideoFlags = 131072i32;
pub const MFVideoFlag_LowerFieldFirst: MFVideoFlags = 262144i32;
pub const MFVideoFlag_BottomUpLinearRep: MFVideoFlags = 524288i32;
pub const MFVideoFlags_DXVASurface: MFVideoFlags = 1048576i32;
pub const MFVideoFlags_RenderTargetSurface: MFVideoFlags = 4194304i32;
pub const MFVideoFlags_ForceQWORD: MFVideoFlags = 2147483647i32;
pub const MFVideoFormat_420O: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1328558644, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_A16B16G16R16F: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 113, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_A2R10G10B10: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 31, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_AI44: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 875841857, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_ARGB32: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 21, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_AV1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 825251393, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_AYUV: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1448433985, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Base: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 0, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Base_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3938695637,
    data2: 48404,
    data3: 16951,
    data4: [143, 31, 186, 180, 40, 228, 147, 18],
};
pub const MFVideoFormat_D16: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 80, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_DV25: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 892499556, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_DV50: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808810084, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_DVH1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 828929636, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_DVHD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1684567652, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_DVSD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1685288548, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_DVSL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1819506276, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_H263: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 859189832, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_H264: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 875967048, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_H264_ES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1061221616,
    data2: 22050,
    data3: 20472,
    data4: [182, 216, 161, 122, 88, 75, 238, 94],
};
pub const MFVideoFormat_H264_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1561127389,
    data2: 38935,
    data3: 18906,
    data4: [189, 253, 245, 245, 185, 143, 24, 166],
};
pub const MFVideoFormat_H265: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 892744264, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_HEVC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1129727304, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_HEVC_ES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1398162760, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_HEVC_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1023283174, data2: 1476, data3: 18396, data4: [157, 112, 75, 219, 41, 89, 114, 15] };
pub const MFVideoFormat_I420: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808596553, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_IYUV: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1448433993, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_L16: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 81, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_L8: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 50, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_M4S2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 844313677, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_MJPG: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1196444237, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_MP43: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 859066445, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_MP4S: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1395937357, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_MP4V: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1446269005, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_MPEG2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3765272614, data2: 56134, data3: 4559, data4: [180, 209, 0, 128, 95, 108, 187, 234] };
pub const MFVideoFormat_MPG1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 826757197, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_MSS1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 827544397, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_MSS2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 844321613, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_NV11: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 825316942, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_NV12: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 842094158, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_NV21: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 825382478, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_ORAW: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1463898703, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_P010: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808530000, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_P016: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 909193296, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_P210: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808530512, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_P216: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 909193808, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_RGB24: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 20, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_RGB32: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 22, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_RGB555: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 24, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_RGB565: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 23, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_RGB8: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 41, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Theora: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1868916852, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_UYVY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1498831189, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_VP10: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808538198, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_VP80: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808996950, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_VP90: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 809062486, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_WMV1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 827739479, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_WMV2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 844516695, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_WMV3: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 861293911, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_WVC1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 826496599, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Y210: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808530521, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Y216: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 909193817, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Y410: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808531033, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Y416: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 909194329, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Y41P: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1345401945, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Y41T: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1412510809, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_Y42T: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1412576345, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_YUY2: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 844715353, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_YV12: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 842094169, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_YVU9: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 961893977, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_YVYU: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1431918169, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_v210: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808530550, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_v216: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 909193846, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
pub const MFVideoFormat_v410: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 808531062, data2: 0, data3: 16, data4: [128, 0, 0, 170, 0, 56, 155, 113] };
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MFVideoInfo {
    pub dwWidth: u32,
    pub dwHeight: u32,
    pub PixelAspectRatio: MFRatio,
    pub SourceChromaSubsampling: MFVideoChromaSubsampling,
    pub InterlaceMode: MFVideoInterlaceMode,
    pub TransferFunction: MFVideoTransferFunction,
    pub ColorPrimaries: MFVideoPrimaries,
    pub TransferMatrix: MFVideoTransferMatrix,
    pub SourceLighting: MFVideoLighting,
    pub FramesPerSecond: MFRatio,
    pub NominalRange: MFNominalRange,
    pub GeometricAperture: MFVideoArea,
    pub MinimumDisplayAperture: MFVideoArea,
    pub PanScanAperture: MFVideoArea,
    pub VideoFlags: u64,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MFVideoInfo {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MFVideoInfo {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFVideoInterlaceMode = i32;
pub const MFVideoInterlace_Unknown: MFVideoInterlaceMode = 0i32;
pub const MFVideoInterlace_Progressive: MFVideoInterlaceMode = 2i32;
pub const MFVideoInterlace_FieldInterleavedUpperFirst: MFVideoInterlaceMode = 3i32;
pub const MFVideoInterlace_FieldInterleavedLowerFirst: MFVideoInterlaceMode = 4i32;
pub const MFVideoInterlace_FieldSingleUpper: MFVideoInterlaceMode = 5i32;
pub const MFVideoInterlace_FieldSingleLower: MFVideoInterlaceMode = 6i32;
pub const MFVideoInterlace_MixedInterlaceOrProgressive: MFVideoInterlaceMode = 7i32;
pub const MFVideoInterlace_Last: MFVideoInterlaceMode = 8i32;
pub const MFVideoInterlace_ForceDWORD: MFVideoInterlaceMode = 2147483647i32;
pub type MFVideoLighting = i32;
pub const MFVideoLighting_Unknown: MFVideoLighting = 0i32;
pub const MFVideoLighting_bright: MFVideoLighting = 1i32;
pub const MFVideoLighting_office: MFVideoLighting = 2i32;
pub const MFVideoLighting_dim: MFVideoLighting = 3i32;
pub const MFVideoLighting_dark: MFVideoLighting = 4i32;
pub const MFVideoLighting_Last: MFVideoLighting = 5i32;
pub const MFVideoLighting_ForceDWORD: MFVideoLighting = 2147483647i32;
pub type MFVideoMixPrefs = i32;
pub const MFVideoMixPrefs_ForceHalfInterlace: MFVideoMixPrefs = 1i32;
pub const MFVideoMixPrefs_AllowDropToHalfInterlace: MFVideoMixPrefs = 2i32;
pub const MFVideoMixPrefs_AllowDropToBob: MFVideoMixPrefs = 4i32;
pub const MFVideoMixPrefs_ForceBob: MFVideoMixPrefs = 8i32;
pub const MFVideoMixPrefs_EnableRotation: MFVideoMixPrefs = 16i32;
pub const MFVideoMixPrefs_Mask: MFVideoMixPrefs = 31i32;
#[repr(C)]
pub struct MFVideoNormalizedRect {
    pub left: f32,
    pub top: f32,
    pub right: f32,
    pub bottom: f32,
}
impl ::core::marker::Copy for MFVideoNormalizedRect {}
impl ::core::clone::Clone for MFVideoNormalizedRect {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFVideoPadFlags = i32;
pub const MFVideoPadFlag_PAD_TO_None: MFVideoPadFlags = 0i32;
pub const MFVideoPadFlag_PAD_TO_4x3: MFVideoPadFlags = 1i32;
pub const MFVideoPadFlag_PAD_TO_16x9: MFVideoPadFlags = 2i32;
pub type MFVideoPrimaries = i32;
pub const MFVideoPrimaries_Unknown: MFVideoPrimaries = 0i32;
pub const MFVideoPrimaries_reserved: MFVideoPrimaries = 1i32;
pub const MFVideoPrimaries_BT709: MFVideoPrimaries = 2i32;
pub const MFVideoPrimaries_BT470_2_SysM: MFVideoPrimaries = 3i32;
pub const MFVideoPrimaries_BT470_2_SysBG: MFVideoPrimaries = 4i32;
pub const MFVideoPrimaries_SMPTE170M: MFVideoPrimaries = 5i32;
pub const MFVideoPrimaries_SMPTE240M: MFVideoPrimaries = 6i32;
pub const MFVideoPrimaries_EBU3213: MFVideoPrimaries = 7i32;
pub const MFVideoPrimaries_SMPTE_C: MFVideoPrimaries = 8i32;
pub const MFVideoPrimaries_BT2020: MFVideoPrimaries = 9i32;
pub const MFVideoPrimaries_XYZ: MFVideoPrimaries = 10i32;
pub const MFVideoPrimaries_DCI_P3: MFVideoPrimaries = 11i32;
pub const MFVideoPrimaries_ACES: MFVideoPrimaries = 12i32;
pub const MFVideoPrimaries_Last: MFVideoPrimaries = 13i32;
pub const MFVideoPrimaries_ForceDWORD: MFVideoPrimaries = 2147483647i32;
pub type MFVideoRenderPrefs = i32;
pub const MFVideoRenderPrefs_DoNotRenderBorder: MFVideoRenderPrefs = 1i32;
pub const MFVideoRenderPrefs_DoNotClipToDevice: MFVideoRenderPrefs = 2i32;
pub const MFVideoRenderPrefs_AllowOutputThrottling: MFVideoRenderPrefs = 4i32;
pub const MFVideoRenderPrefs_ForceOutputThrottling: MFVideoRenderPrefs = 8i32;
pub const MFVideoRenderPrefs_ForceBatching: MFVideoRenderPrefs = 16i32;
pub const MFVideoRenderPrefs_AllowBatching: MFVideoRenderPrefs = 32i32;
pub const MFVideoRenderPrefs_ForceScaling: MFVideoRenderPrefs = 64i32;
pub const MFVideoRenderPrefs_AllowScaling: MFVideoRenderPrefs = 128i32;
pub const MFVideoRenderPrefs_DoNotRepaintOnStop: MFVideoRenderPrefs = 256i32;
pub const MFVideoRenderPrefs_Mask: MFVideoRenderPrefs = 511i32;
pub type MFVideoRotationFormat = i32;
pub const MFVideoRotationFormat_0: MFVideoRotationFormat = 0i32;
pub const MFVideoRotationFormat_90: MFVideoRotationFormat = 90i32;
pub const MFVideoRotationFormat_180: MFVideoRotationFormat = 180i32;
pub const MFVideoRotationFormat_270: MFVideoRotationFormat = 270i32;
pub type MFVideoSphericalFormat = i32;
pub const MFVideoSphericalFormat_Unsupported: MFVideoSphericalFormat = 0i32;
pub const MFVideoSphericalFormat_Equirectangular: MFVideoSphericalFormat = 1i32;
pub const MFVideoSphericalFormat_CubeMap: MFVideoSphericalFormat = 2i32;
pub const MFVideoSphericalFormat_3DMesh: MFVideoSphericalFormat = 3i32;
pub type MFVideoSphericalProjectionMode = i32;
pub const MFVideoSphericalProjectionMode_Spherical: MFVideoSphericalProjectionMode = 0i32;
pub const MFVideoSphericalProjectionMode_Flat: MFVideoSphericalProjectionMode = 1i32;
pub type MFVideoSrcContentHintFlags = i32;
pub const MFVideoSrcContentHintFlag_None: MFVideoSrcContentHintFlags = 0i32;
pub const MFVideoSrcContentHintFlag_16x9: MFVideoSrcContentHintFlags = 1i32;
pub const MFVideoSrcContentHintFlag_235_1: MFVideoSrcContentHintFlags = 2i32;
#[repr(C)]
pub struct MFVideoSurfaceInfo {
    pub Format: u32,
    pub PaletteEntries: u32,
    pub Palette: [MFPaletteEntry; 1],
}
impl ::core::marker::Copy for MFVideoSurfaceInfo {}
impl ::core::clone::Clone for MFVideoSurfaceInfo {
    fn clone(&self) -> Self {
        *self
    }
}
pub type MFVideoTransferFunction = i32;
pub const MFVideoTransFunc_Unknown: MFVideoTransferFunction = 0i32;
pub const MFVideoTransFunc_10: MFVideoTransferFunction = 1i32;
pub const MFVideoTransFunc_18: MFVideoTransferFunction = 2i32;
pub const MFVideoTransFunc_20: MFVideoTransferFunction = 3i32;
pub const MFVideoTransFunc_22: MFVideoTransferFunction = 4i32;
pub const MFVideoTransFunc_709: MFVideoTransferFunction = 5i32;
pub const MFVideoTransFunc_240M: MFVideoTransferFunction = 6i32;
pub const MFVideoTransFunc_sRGB: MFVideoTransferFunction = 7i32;
pub const MFVideoTransFunc_28: MFVideoTransferFunction = 8i32;
pub const MFVideoTransFunc_Log_100: MFVideoTransferFunction = 9i32;
pub const MFVideoTransFunc_Log_316: MFVideoTransferFunction = 10i32;
pub const MFVideoTransFunc_709_sym: MFVideoTransferFunction = 11i32;
pub const MFVideoTransFunc_2020_const: MFVideoTransferFunction = 12i32;
pub const MFVideoTransFunc_2020: MFVideoTransferFunction = 13i32;
pub const MFVideoTransFunc_26: MFVideoTransferFunction = 14i32;
pub const MFVideoTransFunc_2084: MFVideoTransferFunction = 15i32;
pub const MFVideoTransFunc_HLG: MFVideoTransferFunction = 16i32;
pub const MFVideoTransFunc_10_rel: MFVideoTransferFunction = 17i32;
pub const MFVideoTransFunc_Last: MFVideoTransferFunction = 18i32;
pub const MFVideoTransFunc_ForceDWORD: MFVideoTransferFunction = 2147483647i32;
pub type MFVideoTransferMatrix = i32;
pub const MFVideoTransferMatrix_Unknown: MFVideoTransferMatrix = 0i32;
pub const MFVideoTransferMatrix_BT709: MFVideoTransferMatrix = 1i32;
pub const MFVideoTransferMatrix_BT601: MFVideoTransferMatrix = 2i32;
pub const MFVideoTransferMatrix_SMPTE240M: MFVideoTransferMatrix = 3i32;
pub const MFVideoTransferMatrix_BT2020_10: MFVideoTransferMatrix = 4i32;
pub const MFVideoTransferMatrix_BT2020_12: MFVideoTransferMatrix = 5i32;
pub const MFVideoTransferMatrix_Last: MFVideoTransferMatrix = 6i32;
pub const MFVideoTransferMatrix_ForceDWORD: MFVideoTransferMatrix = 2147483647i32;
pub type MFWaveFormatExConvertFlags = i32;
pub const MFWaveFormatExConvertFlag_Normal: MFWaveFormatExConvertFlags = 0i32;
pub const MFWaveFormatExConvertFlag_ForceExtensible: MFWaveFormatExConvertFlags = 1i32;
pub const MF_1024_BYTE_ALIGNMENT: u32 = 1023u32;
pub const MF_128_BYTE_ALIGNMENT: u32 = 127u32;
pub const MF_16_BYTE_ALIGNMENT: u32 = 15u32;
pub const MF_1_BYTE_ALIGNMENT: u32 = 0u32;
pub const MF_2048_BYTE_ALIGNMENT: u32 = 2047u32;
pub const MF_256_BYTE_ALIGNMENT: u32 = 255u32;
pub const MF_2_BYTE_ALIGNMENT: u32 = 1u32;
pub const MF_32_BYTE_ALIGNMENT: u32 = 31u32;
pub const MF_4096_BYTE_ALIGNMENT: u32 = 4095u32;
pub const MF_4_BYTE_ALIGNMENT: u32 = 3u32;
pub const MF_512_BYTE_ALIGNMENT: u32 = 511u32;
pub const MF_64_BYTE_ALIGNMENT: u32 = 63u32;
pub const MF_8192_BYTE_ALIGNMENT: u32 = 8191u32;
pub const MF_8_BYTE_ALIGNMENT: u32 = 7u32;
pub const MF_ACCESS_CONTROLLED_MEDIASOURCE_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 21647409,
    data2: 12037,
    data3: 19562,
    data4: [159, 156, 125, 13, 196, 237, 165, 244],
};
pub type MF_ACTIVATE_CUSTOM_MIXER = i32;
pub const MF_ACTIVATE_CUSTOM_MIXER_ALLOWFAIL: MF_ACTIVATE_CUSTOM_MIXER = 1i32;
pub type MF_ACTIVATE_CUSTOM_PRESENTER = i32;
pub const MF_ACTIVATE_CUSTOM_PRESENTER_ALLOWFAIL: MF_ACTIVATE_CUSTOM_PRESENTER = 1i32;
pub const MF_ACTIVATE_CUSTOM_VIDEO_MIXER_ACTIVATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3125351265,
    data2: 48720,
    data3: 17694,
    data4: [149, 171, 109, 74, 204, 199, 218, 216],
};
pub const MF_ACTIVATE_CUSTOM_VIDEO_MIXER_CLSID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3125351264,
    data2: 48720,
    data3: 17694,
    data4: [149, 171, 109, 74, 204, 199, 218, 216],
};
pub const MF_ACTIVATE_CUSTOM_VIDEO_MIXER_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3125351266,
    data2: 48720,
    data3: 17694,
    data4: [149, 171, 109, 74, 204, 199, 218, 216],
};
pub const MF_ACTIVATE_CUSTOM_VIDEO_PRESENTER_ACTIVATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3125351269,
    data2: 48720,
    data3: 17694,
    data4: [149, 171, 109, 74, 204, 199, 218, 216],
};
pub const MF_ACTIVATE_CUSTOM_VIDEO_PRESENTER_CLSID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3125351268,
    data2: 48720,
    data3: 17694,
    data4: [149, 171, 109, 74, 204, 199, 218, 216],
};
pub const MF_ACTIVATE_CUSTOM_VIDEO_PRESENTER_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3125351270,
    data2: 48720,
    data3: 17694,
    data4: [149, 171, 109, 74, 204, 199, 218, 216],
};
pub const MF_ACTIVATE_MFT_LOCKED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3254126908,
    data2: 32613,
    data3: 20413,
    data4: [158, 57, 95, 174, 195, 196, 251, 215],
};
pub const MF_ACTIVATE_VIDEO_WINDOW: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2586688477,
    data2: 62846,
    data3: 16738,
    data4: [130, 185, 104, 49, 55, 118, 130, 211],
};
pub const MF_API_VERSION: u32 = 112u32;
pub const MF_ASFPROFILE_MAXPACKETSIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 576222759,
    data2: 18398,
    data3: 16744,
    data4: [135, 245, 181, 170, 155, 18, 168, 240],
};
pub const MF_ASFPROFILE_MINPACKETSIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 576222758,
    data2: 18398,
    data3: 16744,
    data4: [135, 245, 181, 170, 155, 18, 168, 240],
};
pub const MF_ASFSTREAMCONFIG_LEAKYBUCKET1: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3332069633,
    data2: 59930,
    data3: 19611,
    data4: [182, 146, 226, 160, 210, 154, 138, 221],
};
pub const MF_ASFSTREAMCONFIG_LEAKYBUCKET2: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3332069634,
    data2: 59930,
    data3: 19611,
    data4: [182, 146, 226, 160, 210, 154, 138, 221],
};
pub type MF_ATTRIBUTES_MATCH_TYPE = i32;
pub const MF_ATTRIBUTES_MATCH_OUR_ITEMS: MF_ATTRIBUTES_MATCH_TYPE = 0i32;
pub const MF_ATTRIBUTES_MATCH_THEIR_ITEMS: MF_ATTRIBUTES_MATCH_TYPE = 1i32;
pub const MF_ATTRIBUTES_MATCH_ALL_ITEMS: MF_ATTRIBUTES_MATCH_TYPE = 2i32;
pub const MF_ATTRIBUTES_MATCH_INTERSECTION: MF_ATTRIBUTES_MATCH_TYPE = 3i32;
pub const MF_ATTRIBUTES_MATCH_SMALLER: MF_ATTRIBUTES_MATCH_TYPE = 4i32;
pub type MF_ATTRIBUTE_SERIALIZE_OPTIONS = i32;
pub const MF_ATTRIBUTE_SERIALIZE_UNKNOWN_BYREF: MF_ATTRIBUTE_SERIALIZE_OPTIONS = 1i32;
pub type MF_ATTRIBUTE_TYPE = i32;
pub const MF_ATTRIBUTE_UINT32: MF_ATTRIBUTE_TYPE = 19i32;
pub const MF_ATTRIBUTE_UINT64: MF_ATTRIBUTE_TYPE = 21i32;
pub const MF_ATTRIBUTE_DOUBLE: MF_ATTRIBUTE_TYPE = 5i32;
pub const MF_ATTRIBUTE_GUID: MF_ATTRIBUTE_TYPE = 72i32;
pub const MF_ATTRIBUTE_STRING: MF_ATTRIBUTE_TYPE = 31i32;
pub const MF_ATTRIBUTE_BLOB: MF_ATTRIBUTE_TYPE = 4113i32;
pub const MF_ATTRIBUTE_IUNKNOWN: MF_ATTRIBUTE_TYPE = 13i32;
pub const MF_AUDIO_RENDERER_ATTRIBUTE_ENDPOINT_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2970267331,
    data2: 61297,
    data3: 19651,
    data4: [184, 115, 5, 169, 160, 139, 159, 142],
};
pub const MF_AUDIO_RENDERER_ATTRIBUTE_ENDPOINT_ROLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1806058751,
    data2: 10181,
    data3: 19714,
    data4: [152, 135, 194, 134, 25, 253, 185, 27],
};
pub const MF_AUDIO_RENDERER_ATTRIBUTE_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3991188960,
    data2: 63493,
    data3: 19820,
    data4: [153, 179, 219, 1, 191, 149, 223, 171],
};
pub const MF_AUDIO_RENDERER_ATTRIBUTE_FLAGS_CROSSPROCESS: u32 = 1u32;
pub const MF_AUDIO_RENDERER_ATTRIBUTE_FLAGS_DONT_ALLOW_FORMAT_CHANGES: u32 = 4u32;
pub const MF_AUDIO_RENDERER_ATTRIBUTE_FLAGS_NOPERSIST: u32 = 2u32;
pub const MF_AUDIO_RENDERER_ATTRIBUTE_SESSION_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3991188963,
    data2: 63493,
    data3: 19820,
    data4: [153, 179, 219, 1, 191, 149, 223, 171],
};
pub const MF_AUDIO_RENDERER_ATTRIBUTE_STREAM_CATEGORY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2843149425,
    data2: 37612,
    data3: 19956,
    data4: [148, 254, 129, 195, 111, 12, 58, 122],
};
pub type MF_AUVRHP_ROOMMODEL = i32;
pub const VRHP_SMALLROOM: MF_AUVRHP_ROOMMODEL = 0i32;
pub const VRHP_MEDIUMROOM: MF_AUVRHP_ROOMMODEL = 1i32;
pub const VRHP_BIGROOM: MF_AUVRHP_ROOMMODEL = 2i32;
pub const VRHP_CUSTUMIZEDROOM: MF_AUVRHP_ROOMMODEL = 3i32;
pub const MF_BD_MVC_PLANE_OFFSET_METADATA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1655067876, data2: 46956, data3: 18689, data4: [152, 35, 44, 182, 21, 212, 115, 24] };
pub const MF_BOOT_DRIVER_VERIFICATION_FAILED: u32 = 1048576u32;
pub const MF_BYTESTREAMHANDLER_ACCEPTS_SHARE_WRITE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2799826739, data2: 12289, data3: 18709, data4: [129, 80, 21, 88, 162, 24, 14, 200] };
pub const MF_BYTESTREAM_CONTENT_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4231365257, data2: 15542, data3: 17932, data4: [164, 36, 182, 104, 18, 96, 55, 90] };
pub const MF_BYTESTREAM_DLNA_PROFILE_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4231365261, data2: 15542, data3: 17932, data4: [164, 36, 182, 104, 18, 96, 55, 90] };
pub const MF_BYTESTREAM_DURATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4231365258, data2: 15542, data3: 17932, data4: [164, 36, 182, 104, 18, 96, 55, 90] };
pub const MF_BYTESTREAM_EFFECTIVE_URL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2600075785,
    data2: 35281,
    data3: 17071,
    data4: [132, 86, 29, 230, 181, 98, 214, 145],
};
pub const MF_BYTESTREAM_IFO_FILE_URI: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4231365260, data2: 15542, data3: 17932, data4: [164, 36, 182, 104, 18, 96, 55, 90] };
pub const MF_BYTESTREAM_LAST_MODIFIED_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4231365259, data2: 15542, data3: 17932, data4: [164, 36, 182, 104, 18, 96, 55, 90] };
pub const MF_BYTESTREAM_ORIGIN_NAME: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4231365256, data2: 15542, data3: 17932, data4: [164, 36, 182, 104, 18, 96, 55, 90] };
pub const MF_BYTESTREAM_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2869059115, data2: 5849, data3: 16768, data4: [161, 39, 186, 108, 112, 21, 97, 97] };
pub const MF_BYTESTREAM_TRANSCODED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3066413698,
    data2: 19913,
    data3: 19897,
    data4: [171, 72, 207, 59, 109, 139, 197, 224],
};
#[repr(C)]
pub struct MF_BYTE_STREAM_CACHE_RANGE {
    pub qwStartOffset: u64,
    pub qwEndOffset: u64,
}
impl ::core::marker::Copy for MF_BYTE_STREAM_CACHE_RANGE {}
impl ::core::clone::Clone for MF_BYTE_STREAM_CACHE_RANGE {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MF_CAPTURE_ENGINE_ALL_EFFECTS_REMOVED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4260197665,
    data2: 36568,
    data3: 17178,
    data4: [169, 107, 243, 226, 86, 94, 152, 28],
};
pub const MF_CAPTURE_ENGINE_AUDIO_PROCESSING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 284278366, data2: 32273, data3: 16651, data4: [151, 61, 244, 182, 16, 144, 0, 254] };
pub type MF_CAPTURE_ENGINE_AUDIO_PROCESSING_MODE = i32;
pub const MF_CAPTURE_ENGINE_AUDIO_PROCESSING_DEFAULT: MF_CAPTURE_ENGINE_AUDIO_PROCESSING_MODE = 0i32;
pub const MF_CAPTURE_ENGINE_AUDIO_PROCESSING_RAW: MF_CAPTURE_ENGINE_AUDIO_PROCESSING_MODE = 1i32;
pub const MF_CAPTURE_ENGINE_CAMERA_STREAM_BLOCKED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2753598487, data2: 36153, data3: 18163, data4: [183, 89, 89, 18, 82, 143, 66, 7] };
pub const MF_CAPTURE_ENGINE_CAMERA_STREAM_UNBLOCKED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2615799536,
    data2: 52655,
    data3: 18199,
    data4: [133, 100, 131, 74, 174, 102, 65, 92],
};
pub const MF_CAPTURE_ENGINE_D3D_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1994546811,
    data2: 54677,
    data3: 17027,
    data4: [150, 44, 197, 148, 175, 215, 141, 223],
};
pub const MF_CAPTURE_ENGINE_DECODER_MFT_FIELDOFUSE_UNLOCK_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 730518248, data2: 31435, data3: 17185, data4: [166, 6, 50, 92, 66, 73, 244, 252] };
pub type MF_CAPTURE_ENGINE_DEVICE_TYPE = i32;
pub const MF_CAPTURE_ENGINE_DEVICE_TYPE_AUDIO: MF_CAPTURE_ENGINE_DEVICE_TYPE = 0i32;
pub const MF_CAPTURE_ENGINE_DEVICE_TYPE_VIDEO: MF_CAPTURE_ENGINE_DEVICE_TYPE = 1i32;
pub const MF_CAPTURE_ENGINE_DISABLE_DXVA: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4186015842,
    data2: 6045,
    data3: 17215,
    data4: [163, 47, 116, 203, 207, 116, 70, 109],
};
pub const MF_CAPTURE_ENGINE_DISABLE_HARDWARE_TRANSFORMS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3083086443,
    data2: 12807,
    data3: 17557,
    data4: [180, 231, 129, 249, 195, 93, 89, 145],
};
pub const MF_CAPTURE_ENGINE_EFFECT_ADDED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2861418421,
    data2: 41032,
    data3: 19987,
    data4: [142, 190, 242, 60, 70, 200, 48, 193],
};
pub const MF_CAPTURE_ENGINE_EFFECT_REMOVED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3337149191,
    data2: 64265,
    data3: 19016,
    data4: [137, 198, 191, 146, 160, 66, 34, 201],
};
pub const MF_CAPTURE_ENGINE_ENABLE_CAMERA_STREAMSTATE_NOTIFICATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1283493533, data2: 43757, data3: 18195, data4: [144, 251, 203, 36, 6, 74, 184, 218] };
pub const MF_CAPTURE_ENGINE_ENCODER_MFT_FIELDOFUSE_UNLOCK_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1422277120,
    data2: 30933,
    data3: 16943,
    data4: [170, 62, 94, 153, 172, 100, 146, 105],
};
pub const MF_CAPTURE_ENGINE_ERROR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1186504646,
    data2: 13260,
    data3: 17305,
    data4: [157, 173, 120, 77, 231, 125, 88, 124],
};
pub const MF_CAPTURE_ENGINE_EVENT_GENERATOR_GUID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2885323477,
    data2: 64621,
    data3: 18705,
    data4: [135, 224, 150, 25, 69, 248, 247, 206],
};
pub const MF_CAPTURE_ENGINE_EVENT_STREAM_INDEX: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2187951940,
    data2: 45519,
    data3: 17131,
    data4: [151, 83, 248, 109, 100, 156, 136, 101],
};
pub const MF_CAPTURE_ENGINE_INITIALIZED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 563712700,
    data2: 53138,
    data3: 17713,
    data4: [161, 174, 150, 225, 232, 134, 200, 241],
};
pub const MF_CAPTURE_ENGINE_MEDIASOURCE_CONFIG: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3161033170,
    data2: 4033,
    data3: 18145,
    data4: [167, 79, 239, 211, 107, 199, 136, 222],
};
pub const MF_CAPTURE_ENGINE_MEDIA_CATEGORY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2386516949,
    data2: 56255,
    data3: 17136,
    data4: [133, 66, 208, 122, 57, 113, 118, 42],
};
pub type MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE = i32;
pub const MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE_OTHER: MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE = 0i32;
pub const MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE_COMMUNICATIONS: MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE = 1i32;
pub const MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE_MEDIA: MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE = 2i32;
pub const MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE_GAMECHAT: MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE = 3i32;
pub const MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE_SPEECH: MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE = 4i32;
pub const MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE_FARFIELDSPEECH: MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE = 5i32;
pub const MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE_UNIFORMSPEECH: MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE = 6i32;
pub const MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE_VOICETYPING: MF_CAPTURE_ENGINE_MEDIA_CATEGORY_TYPE = 7i32;
pub const MF_CAPTURE_ENGINE_OUTPUT_MEDIA_TYPE_SET: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3400194452, data2: 33772, data3: 17897, data4: [163, 10, 31, 32, 170, 219, 152, 49] };
pub const MF_CAPTURE_ENGINE_PHOTO_TAKEN: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1011926085,
    data2: 29444,
    data3: 18667,
    data4: [134, 93, 187, 161, 155, 163, 175, 92],
};
pub const MF_CAPTURE_ENGINE_PREVIEW_STARTED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2752962337, data2: 63955, data3: 19060, data4: [153, 27, 184, 23, 41, 137, 82, 196] };
pub const MF_CAPTURE_ENGINE_PREVIEW_STOPPED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 332731452, data2: 7901, data3: 20048, data4: [162, 239, 53, 10, 71, 103, 128, 96] };
pub const MF_CAPTURE_ENGINE_RECORD_SINK_AUDIO_MAX_PROCESSED_SAMPLES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2560024874,
    data2: 63239,
    data3: 17664,
    data4: [182, 189, 219, 142, 184, 16, 181, 15],
};
pub const MF_CAPTURE_ENGINE_RECORD_SINK_AUDIO_MAX_UNPROCESSED_SAMPLES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 484290881, data2: 42996, data3: 19800, data4: [152, 150, 77, 21, 165, 60, 78, 254] };
pub const MF_CAPTURE_ENGINE_RECORD_SINK_VIDEO_MAX_PROCESSED_SAMPLES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3887375518, data2: 14380, data3: 19183, data4: [169, 70, 174, 213, 73, 11, 113, 17] };
pub const MF_CAPTURE_ENGINE_RECORD_SINK_VIDEO_MAX_UNPROCESSED_SAMPLES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3026712325,
    data2: 30995,
    data3: 18580,
    data4: [157, 66, 162, 21, 254, 162, 61, 169],
};
pub const MF_CAPTURE_ENGINE_RECORD_STARTED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2888499835,
    data2: 56825,
    data3: 18592,
    data4: [137, 190, 56, 171, 53, 239, 69, 192],
};
pub const MF_CAPTURE_ENGINE_RECORD_STOPPED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1441079306,
    data2: 63887,
    data3: 19469,
    data4: [169, 236, 158, 178, 94, 211, 215, 115],
};
pub const MF_CAPTURE_ENGINE_SELECTEDCAMERAPROFILE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 51776382, data2: 7279, data3: 19890, data4: [173, 86, 167, 196, 48, 248, 35, 146] };
pub const MF_CAPTURE_ENGINE_SELECTEDCAMERAPROFILE_INDEX: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1021871635,
    data2: 8724,
    data3: 18115,
    data4: [180, 23, 130, 248, 163, 19, 201, 195],
};
pub type MF_CAPTURE_ENGINE_SINK_TYPE = i32;
pub const MF_CAPTURE_ENGINE_SINK_TYPE_RECORD: MF_CAPTURE_ENGINE_SINK_TYPE = 0i32;
pub const MF_CAPTURE_ENGINE_SINK_TYPE_PREVIEW: MF_CAPTURE_ENGINE_SINK_TYPE = 1i32;
pub const MF_CAPTURE_ENGINE_SINK_TYPE_PHOTO: MF_CAPTURE_ENGINE_SINK_TYPE = 2i32;
pub type MF_CAPTURE_ENGINE_SOURCE = u32;
pub const MF_CAPTURE_ENGINE_PREFERRED_SOURCE_STREAM_FOR_VIDEO_PREVIEW: MF_CAPTURE_ENGINE_SOURCE = 4294967290u32;
pub const MF_CAPTURE_ENGINE_PREFERRED_SOURCE_STREAM_FOR_VIDEO_RECORD: MF_CAPTURE_ENGINE_SOURCE = 4294967289u32;
pub const MF_CAPTURE_ENGINE_PREFERRED_SOURCE_STREAM_FOR_PHOTO: MF_CAPTURE_ENGINE_SOURCE = 4294967288u32;
pub const MF_CAPTURE_ENGINE_PREFERRED_SOURCE_STREAM_FOR_AUDIO: MF_CAPTURE_ENGINE_SOURCE = 4294967287u32;
pub const MF_CAPTURE_ENGINE_PREFERRED_SOURCE_STREAM_FOR_METADATA: MF_CAPTURE_ENGINE_SOURCE = 4294967286u32;
pub const MF_CAPTURE_ENGINE_MEDIASOURCE: MF_CAPTURE_ENGINE_SOURCE = 4294967295u32;
pub type MF_CAPTURE_ENGINE_STREAM_CATEGORY = i32;
pub const MF_CAPTURE_ENGINE_STREAM_CATEGORY_VIDEO_PREVIEW: MF_CAPTURE_ENGINE_STREAM_CATEGORY = 0i32;
pub const MF_CAPTURE_ENGINE_STREAM_CATEGORY_VIDEO_CAPTURE: MF_CAPTURE_ENGINE_STREAM_CATEGORY = 1i32;
pub const MF_CAPTURE_ENGINE_STREAM_CATEGORY_PHOTO_INDEPENDENT: MF_CAPTURE_ENGINE_STREAM_CATEGORY = 2i32;
pub const MF_CAPTURE_ENGINE_STREAM_CATEGORY_PHOTO_DEPENDENT: MF_CAPTURE_ENGINE_STREAM_CATEGORY = 3i32;
pub const MF_CAPTURE_ENGINE_STREAM_CATEGORY_AUDIO: MF_CAPTURE_ENGINE_STREAM_CATEGORY = 4i32;
pub const MF_CAPTURE_ENGINE_STREAM_CATEGORY_UNSUPPORTED: MF_CAPTURE_ENGINE_STREAM_CATEGORY = 5i32;
pub const MF_CAPTURE_ENGINE_STREAM_CATEGORY_METADATA: MF_CAPTURE_ENGINE_STREAM_CATEGORY = 6i32;
pub const MF_CAPTURE_ENGINE_USE_AUDIO_DEVICE_ONLY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 478181338, data2: 33894, data3: 19908, data4: [139, 142, 39, 107, 63, 133, 146, 59] };
pub const MF_CAPTURE_ENGINE_USE_VIDEO_DEVICE_ONLY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2114081137, data2: 53042, data3: 20270, data4: [143, 25, 65, 5, 119, 183, 58, 102] };
pub const MF_CAPTURE_METADATA_DIGITALWINDOW: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 661615266, data2: 22984, data3: 20329, data4: [151, 180, 6, 139, 140, 14, 192, 68] };
pub const MF_CAPTURE_METADATA_EXIF: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 781546936,
    data2: 35889,
    data3: 18946,
    data4: [133, 117, 66, 177, 151, 183, 21, 146],
};
pub const MF_CAPTURE_METADATA_EXPOSURE_COMPENSATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3516443253,
    data2: 19298,
    data3: 17221,
    data4: [171, 243, 60, 49, 250, 18, 194, 153],
};
pub const MF_CAPTURE_METADATA_EXPOSURE_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 381267609,
    data2: 52612,
    data3: 16483,
    data4: [135, 157, 162, 140, 118, 51, 114, 158],
};
pub const MF_CAPTURE_METADATA_FACEROICHARACTERIZATIONS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3106382248,
    data2: 6383,
    data3: 18131,
    data4: [179, 175, 105, 55, 47, 148, 217, 178],
};
pub const MF_CAPTURE_METADATA_FACEROIS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2253333926, data2: 13471, data3: 18097, data4: [163, 14, 84, 204, 34, 146, 138, 71] };
pub const MF_CAPTURE_METADATA_FACEROITIMESTAMPS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3914158284,
    data2: 15776,
    data3: 17620,
    data4: [187, 52, 131, 25, 138, 116, 24, 104],
};
pub const MF_CAPTURE_METADATA_FIRST_SCANLINE_START_TIME_QPC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1781287409,
    data2: 57426,
    data3: 18102,
    data4: [178, 217, 115, 193, 85, 135, 9, 175],
};
pub const MF_CAPTURE_METADATA_FLASH: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1246843403, data2: 64310, data3: 17516, data4: [157, 242, 104, 23, 27, 154, 3, 137] };
pub const MF_CAPTURE_METADATA_FLASH_POWER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2618166601, data2: 517, data3: 18714, data4: [188, 157, 45, 110, 31, 77, 86, 132] };
pub const MF_CAPTURE_METADATA_FOCUSSTATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2826887508, data2: 39295, data3: 18013, data4: [185, 31, 41, 213, 59, 152, 43, 136] };
pub const MF_CAPTURE_METADATA_FRAME_BACKGROUND_MASK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 66145747, data2: 30173, data3: 17210, data4: [168, 226, 30, 63, 95, 42, 80, 160] };
pub const MF_CAPTURE_METADATA_FRAME_ILLUMINATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1835569148,
    data2: 25555,
    data3: 18174,
    data4: [186, 218, 91, 148, 125, 176, 208, 128],
};
pub const MF_CAPTURE_METADATA_FRAME_RAWSTREAM: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2454849403, data2: 9856, data3: 18873, data4: [174, 2, 177, 144, 117, 151, 59, 112] };
pub const MF_CAPTURE_METADATA_HISTOGRAM: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2234876978,
    data2: 12022,
    data3: 19369,
    data4: [163, 251, 6, 216, 41, 116, 184, 149],
};
pub const MF_CAPTURE_METADATA_ISO_GAINS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 92285641, data2: 3613, data3: 16839, data4: [168, 200, 126, 115, 105, 248, 78, 30] };
pub const MF_CAPTURE_METADATA_ISO_SPEED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3844646543, data2: 45795, data3: 17662, data4: [139, 101, 7, 191, 75, 90, 19, 255] };
pub const MF_CAPTURE_METADATA_LAST_SCANLINE_END_TIME_QPC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3704282827,
    data2: 50388,
    data3: 16397,
    data4: [180, 24, 16, 232, 133, 37, 225, 246],
};
pub const MF_CAPTURE_METADATA_LENS_POSITION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3053227654, data2: 4561, data3: 20080, data4: [129, 155, 114, 58, 137, 250, 69, 32] };
pub const MF_CAPTURE_METADATA_PHOTO_FRAME_FLASH: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 262002374, data2: 24579, data3: 17880, data4: [189, 89, 241, 245, 62, 61, 4, 232] };
pub const MF_CAPTURE_METADATA_REQUESTED_FRAME_SETTING_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3140949721,
    data2: 35425,
    data3: 18340,
    data4: [129, 151, 69, 156, 127, 241, 116, 213],
};
pub const MF_CAPTURE_METADATA_SCANLINE_DIRECTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1687593914,
    data2: 6407,
    data3: 18918,
    data4: [176, 195, 18, 55, 149, 243, 128, 169],
};
pub const MF_CAPTURE_METADATA_SCANLINE_TIME_QPC_ACCURACY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1289198673,
    data2: 63333,
    data3: 19209,
    data4: [177, 225, 39, 209, 247, 235, 234, 9],
};
pub const MF_CAPTURE_METADATA_SCENE_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2630071629,
    data2: 24275,
    data3: 19374,
    data4: [179, 136, 118, 112, 174, 245, 158, 19],
};
pub const MF_CAPTURE_METADATA_SENSORFRAMERATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3679532414, data2: 40253, data3: 18786, data4: [176, 109, 7, 206, 101, 13, 154, 10] };
pub const MF_CAPTURE_METADATA_UVC_PAYLOADHEADER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4193815175,
    data2: 57821,
    data3: 17438,
    data4: [149, 203, 66, 226, 26, 100, 241, 217],
};
pub const MF_CAPTURE_METADATA_WHITEBALANCE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3342269815,
    data2: 4025,
    data3: 20014,
    data4: [151, 162, 252, 212, 144, 115, 158, 233],
};
pub const MF_CAPTURE_METADATA_WHITEBALANCE_GAINS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3881241743,
    data2: 11723,
    data3: 19580,
    data4: [170, 206, 34, 236, 231, 204, 230, 71],
};
pub const MF_CAPTURE_METADATA_ZOOMFACTOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3842706305,
    data2: 58625,
    data3: 17090,
    data4: [171, 242, 133, 126, 203, 19, 250, 92],
};
pub const MF_CAPTURE_SINK_PREPARED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2080170583,
    data2: 4785,
    data3: 17417,
    data4: [140, 52, 212, 69, 218, 171, 117, 120],
};
pub const MF_CAPTURE_SOURCE_CURRENT_DEVICE_MEDIA_TYPE_SET: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3890699852, data2: 924, data3: 17424, data4: [129, 91, 135, 65, 48, 123, 99, 170] };
pub const MF_COMPONENT_CERT_REVOKED: u32 = 32768u32;
pub const MF_COMPONENT_HS_CERT_REVOKED: u32 = 131072u32;
pub const MF_COMPONENT_INVALID_EKU: u32 = 16384u32;
pub const MF_COMPONENT_INVALID_ROOT: u32 = 65536u32;
pub const MF_COMPONENT_LS_CERT_REVOKED: u32 = 262144u32;
pub const MF_COMPONENT_REVOKED: u32 = 8192u32;
pub type MF_CONNECT_METHOD = i32;
pub const MF_CONNECT_DIRECT: MF_CONNECT_METHOD = 0i32;
pub const MF_CONNECT_ALLOW_CONVERTER: MF_CONNECT_METHOD = 1i32;
pub const MF_CONNECT_ALLOW_DECODER: MF_CONNECT_METHOD = 3i32;
pub const MF_CONNECT_RESOLVE_INDEPENDENT_OUTPUTTYPES: MF_CONNECT_METHOD = 4i32;
pub const MF_CONNECT_AS_OPTIONAL: MF_CONNECT_METHOD = 65536i32;
pub const MF_CONNECT_AS_OPTIONAL_BRANCH: MF_CONNECT_METHOD = 131072i32;
pub const MF_CONTENTDECRYPTIONMODULE_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 355601477, data2: 65408, data3: 18506, data4: [157, 203, 13, 248, 148, 230, 154, 1] };
pub const MF_CONTENT_DECRYPTOR_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1755785511,
    data2: 64635,
    data3: 17646,
    data4: [133, 244, 124, 81, 189, 85, 166, 89],
};
pub const MF_CONTENT_PROTECTION_DEVICE_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4283974511,
    data2: 30368,
    data3: 16894,
    data4: [181, 102, 16, 204, 83, 150, 46, 221],
};
pub type MF_CROSS_ORIGIN_POLICY = i32;
pub const MF_CROSS_ORIGIN_POLICY_NONE: MF_CROSS_ORIGIN_POLICY = 0i32;
pub const MF_CROSS_ORIGIN_POLICY_ANONYMOUS: MF_CROSS_ORIGIN_POLICY = 1i32;
pub const MF_CROSS_ORIGIN_POLICY_USE_CREDENTIALS: MF_CROSS_ORIGIN_POLICY = 2i32;
pub type MF_CUSTOM_DECODE_UNIT_TYPE = i32;
pub const MF_DECODE_UNIT_NAL: MF_CUSTOM_DECODE_UNIT_TYPE = 0i32;
pub const MF_DECODE_UNIT_SEI: MF_CUSTOM_DECODE_UNIT_TYPE = 1i32;
pub const MF_D3D12_SYNCHRONIZATION_OBJECT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 712805738, data2: 34214, data3: 18765, data4: [160, 70, 6, 234, 26, 19, 143, 75] };
pub const MF_DECODER_FWD_CUSTOM_SEI_DECODE_ORDER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4047224380,
    data2: 14036,
    data3: 16650,
    data4: [185, 133, 122, 149, 26, 30, 98, 148],
};
pub const MF_DEVICEMFT_CONNECTED_FILTER_KSCONTROL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1781288870,
    data2: 53625,
    data3: 16845,
    data4: [149, 35, 130, 35, 113, 234, 64, 229],
};
pub const MF_DEVICEMFT_CONNECTED_PIN_KSCONTROL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3862106359,
    data2: 45636,
    data3: 20216,
    data4: [154, 125, 36, 199, 78, 50, 235, 208],
};
pub const MF_DEVICEMFT_EXTENSION_PLUGIN_CLSID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 138730414,
    data2: 13562,
    data3: 18592,
    data4: [167, 131, 142, 105, 111, 177, 201, 168],
};
pub const MF_DEVICEMFT_SENSORPROFILE_COLLECTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 921427012, data2: 45356, data3: 17435, data4: [137, 244, 8, 178, 244, 26, 156, 252] };
pub const MF_DEVICESTREAM_ATTRIBUTE_FACEAUTH_CAPABILITY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3413102890,
    data2: 8776,
    data3: 20033,
    data4: [173, 70, 231, 139, 185, 10, 185, 252],
};
pub const MF_DEVICESTREAM_ATTRIBUTE_FRAMESOURCE_TYPES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 387211217, data2: 6955, data3: 16956, data4: [128, 1, 43, 104, 51, 237, 53, 136] };
pub const MF_DEVICESTREAM_ATTRIBUTE_SECURE_CAPABILITY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2484065830,
    data2: 60014,
    data3: 18052,
    data4: [152, 64, 54, 189, 110, 201, 251, 239],
};
pub const MF_DEVICESTREAM_EXTENSION_PLUGIN_CLSID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 76440920, data2: 24772, data3: 16755, data4: [189, 91, 106, 60, 162, 137, 106, 238] };
pub const MF_DEVICESTREAM_EXTENSION_PLUGIN_CONNECTION_POINT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 939079516,
    data2: 58980,
    data3: 20132,
    data4: [170, 228, 203, 109, 29, 172, 161, 244],
};
pub const MF_DEVICESTREAM_FILTER_KSCONTROL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1182285002,
    data2: 15861,
    data3: 18723,
    data4: [169, 239, 54, 183, 34, 62, 221, 224],
};
pub const MF_DEVICESTREAM_FRAMESERVER_HIDDEN: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4093793915, data2: 19857, data3: 16761, data4: [150, 209, 116, 200, 72, 12, 32, 52] };
pub const MF_DEVICESTREAM_FRAMESERVER_SHARED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 481523945, data2: 45689, data3: 16852, data4: [175, 151, 52, 162, 67, 230, 131, 32] };
pub const MF_DEVICESTREAM_IMAGE_STREAM: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2818553957,
    data2: 59314,
    data3: 17328,
    data4: [159, 111, 154, 242, 160, 229, 15, 192],
};
pub const MF_DEVICESTREAM_INDEPENDENT_IMAGE_STREAM: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 65989758,
    data2: 54789,
    data3: 17782,
    data4: [139, 41, 101, 128, 180, 144, 215, 211],
};
pub const MF_DEVICESTREAM_MAX_FRAME_BUFFERS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 377802430, data2: 12661, data3: 18821, data4: [136, 44, 14, 253, 62, 138, 193, 30] };
pub const MF_DEVICESTREAM_MULTIPLEXED_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1856324272, data2: 10271, data3: 16945, data4: [164, 100, 254, 47, 80, 34, 80, 28] };
pub const MF_DEVICESTREAM_PIN_KSCONTROL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4013881767,
    data2: 34802,
    data3: 18634,
    data4: [190, 2, 103, 72, 120, 145, 142, 152],
};
pub const MF_DEVICESTREAM_REQUIRED_CAPABILITIES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1837864318, data2: 31990, data3: 17396, data4: [175, 86, 156, 14, 30, 79, 203, 225] };
pub const MF_DEVICESTREAM_REQUIRED_SDDL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 857401437,
    data2: 49363,
    data3: 18874,
    data4: [131, 186, 130, 161, 45, 99, 205, 214],
};
pub const MF_DEVICESTREAM_SENSORSTREAM_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3814432740, data2: 1625, data3: 19629, data4: [187, 81, 51, 22, 11, 231, 228, 19] };
pub const MF_DEVICESTREAM_SOURCE_ATTRIBUTES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 797750807,
    data2: 13851,
    data3: 17231,
    data4: [133, 234, 153, 160, 62, 28, 228, 224],
};
pub const MF_DEVICESTREAM_STREAM_CATEGORY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 691660728, data2: 42542, data3: 17785, data4: [182, 116, 212, 7, 61, 250, 187, 186] };
pub const MF_DEVICESTREAM_STREAM_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 297619744, data2: 53540, data3: 17515, data4: [136, 230, 23, 6, 2, 87, 255, 249] };
pub const MF_DEVICESTREAM_TAKEPHOTO_TRIGGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 488115764,
    data2: 21388,
    data3: 20411,
    data4: [167, 90, 133, 154, 247, 210, 97, 166],
};
pub const MF_DEVICESTREAM_TRANSFORM_STREAM_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3862509495,
    data2: 55983,
    data3: 19785,
    data4: [129, 95, 216, 38, 248, 173, 49, 231],
};
pub const MF_DEVICE_THERMAL_STATE_CHANGED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1892470959,
    data2: 64671,
    data3: 19947,
    data4: [168, 117, 159, 236, 209, 108, 91, 212],
};
pub const MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1624302937,
    data2: 21240,
    data3: 20386,
    data4: [187, 206, 172, 219, 52, 168, 236, 1],
};
pub const MF_DEVSOURCE_ATTRIBUTE_MEDIA_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1453857226, data2: 3192, data3: 19940, data4: [160, 167, 61, 218, 186, 15, 36, 212] };
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_PASSWORD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2700967446,
    data2: 17113,
    data3: 18911,
    data4: [132, 192, 232, 44, 94, 171, 136, 116],
};
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_STREAM_URL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2642100434,
    data2: 13847,
    data3: 16451,
    data4: [147, 227, 141, 109, 169, 187, 52, 146],
};
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3322594814,
    data2: 9514,
    data3: 18319,
    data4: [160, 239, 188, 143, 165, 247, 202, 211],
};
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_AUDCAP_ENDPOINT_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 819630680, data2: 65209, data3: 18343, data4: [164, 83, 118, 58, 122, 142, 28, 95] };
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_AUDCAP_GUID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 350067228,
    data2: 31999,
    data3: 16830,
    data4: [177, 185, 186, 26, 198, 236, 181, 113],
};
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_AUDCAP_ROLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3164410254, data2: 35943, data3: 18968, data4: [133, 212, 18, 211, 0, 64, 5, 82] };
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_AUDCAP_SYMBOLIC_LINK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2563918686, data2: 22832, data3: 17940, data4: [181, 161, 246, 0, 249, 53, 90, 120] };
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_CATEGORY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2012261993, data2: 50109, data3: 17673, data4: [148, 29, 70, 126, 77, 36, 137, 158] };
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2328057978, data2: 19175, data3: 17112, data4: [153, 224, 10, 96, 19, 238, 249, 15] };
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_HW_SOURCE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3731900090,
    data2: 21718,
    data3: 17543,
    data4: [162, 164, 236, 124, 13, 27, 209, 99],
};
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_MAX_BUFFERS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2111420208,
    data2: 20269,
    data3: 16853,
    data4: [143, 149, 12, 201, 169, 18, 186, 38],
};
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_PROVIDER_DEVICE_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 912825666, data2: 41068, data3: 16558, data4: [132, 207, 245, 160, 52, 6, 124, 196] };
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1492167384,
    data2: 8895,
    data3: 20362,
    data4: [187, 61, 210, 196, 151, 140, 110, 47],
};
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_USERNAME: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 97524445, data2: 38047, data3: 18155, data4: [188, 142, 139, 13, 43, 50, 215, 157] };
pub const MF_DEVSOURCE_ATTRIBUTE_SOURCE_XADDRESS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3164651090,
    data2: 49959,
    data3: 17607,
    data4: [155, 125, 127, 168, 217, 181, 188, 218],
};
pub const MF_DISABLE_FRAME_CORRUPTION_INFO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1887887724,
    data2: 18885,
    data3: 16897,
    data4: [136, 42, 133, 56, 243, 140, 241, 58],
};
pub const MF_DISABLE_LOCALLY_REGISTERED_PLUGINS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1722903977, data2: 44500, data3: 18400, data4: [161, 107, 90, 241, 251, 72, 54, 52] };
pub const MF_DMFT_FRAME_BUFFER_INFO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 963437001, data2: 26537, data3: 17740, data4: [135, 151, 149, 164, 87, 153, 216, 4] };
pub const MF_ENABLE_3DVIDEO_OUTPUT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3182263242, data2: 3679, data3: 19216, data4: [171, 22, 38, 222, 56, 27, 98, 147] };
pub const MF_EVENT_DO_THINNING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 840869627, data2: 56025, data3: 18148, data4: [179, 29, 210, 234, 231, 9, 14, 48] };
pub const MF_EVENT_MFT_CONTEXT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3083678193,
    data2: 35230,
    data3: 19265,
    data4: [128, 201, 38, 168, 150, 211, 41, 119],
};
pub const MF_EVENT_MFT_INPUT_STREAM_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4070321354,
    data2: 31462,
    data3: 17106,
    data4: [178, 132, 191, 131, 124, 200, 116, 226],
};
pub const MF_EVENT_OUTPUT_NODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2198805131, data2: 49248, data3: 18141, data4: [168, 1, 28, 149, 222, 201, 177, 7] };
pub const MF_EVENT_PRESENTATION_TIME_OFFSET: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1524176081,
    data2: 39749,
    data3: 19085,
    data4: [162, 192, 129, 209, 229, 11, 251, 7],
};
pub const MF_EVENT_SCRUBSAMPLE_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2596737715, data2: 56504, data3: 17621, data4: [141, 12, 55, 69, 90, 39, 130, 227] };
pub const MF_EVENT_SESSIONCAPS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2120137936, data2: 4536, data3: 19134, data4: [175, 173, 16, 246, 89, 154, 127, 66] };
pub const MF_EVENT_SESSIONCAPS_DELTA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2120137937, data2: 4536, data3: 19134, data4: [175, 173, 16, 246, 89, 154, 127, 66] };
pub const MF_EVENT_SOURCE_ACTUAL_START: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2831963561, data2: 27441, data3: 16799, data4: [132, 93, 255, 179, 81, 162, 67, 75] };
pub const MF_EVENT_SOURCE_CHARACTERISTICS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1205568656,
    data2: 35618,
    data3: 20306,
    data4: [175, 218, 156, 225, 178, 211, 207, 168],
};
pub const MF_EVENT_SOURCE_CHARACTERISTICS_OLD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1205568657,
    data2: 35618,
    data3: 20306,
    data4: [175, 218, 156, 225, 178, 211, 207, 168],
};
pub const MF_EVENT_SOURCE_FAKE_START: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2831963559, data2: 27441, data3: 16799, data4: [132, 93, 255, 179, 81, 162, 67, 75] };
pub const MF_EVENT_SOURCE_PROJECTSTART: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2831963560, data2: 27441, data3: 16799, data4: [132, 93, 255, 179, 81, 162, 67, 75] };
pub const MF_EVENT_SOURCE_TOPOLOGY_CANCELED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3680695888,
    data2: 39518,
    data3: 18180,
    data4: [172, 243, 86, 59, 198, 167, 51, 100],
};
pub const MF_EVENT_START_PRESENTATION_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1524176080,
    data2: 39749,
    data3: 19085,
    data4: [162, 192, 129, 209, 229, 11, 251, 7],
};
pub const MF_EVENT_START_PRESENTATION_TIME_AT_OUTPUT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1524176082,
    data2: 39749,
    data3: 19085,
    data4: [162, 192, 129, 209, 229, 11, 251, 7],
};
pub const MF_EVENT_STREAM_METADATA_CONTENT_KEYIDS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1348682909, data2: 52265, data3: 20422, data4: [167, 90, 210, 71, 179, 90, 248, 92] };
pub const MF_EVENT_STREAM_METADATA_KEYDATA: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3445204129,
    data2: 19003,
    data3: 19389,
    data4: [134, 101, 114, 164, 15, 190, 167, 118],
};
pub const MF_EVENT_STREAM_METADATA_SYSTEMID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 513994596, data2: 47638, data3: 18998, data4: [135, 25, 254, 117, 96, 186, 50, 173] };
pub const MF_EVENT_TOPOLOGY_STATUS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 818217357,
    data2: 39507,
    data3: 17739,
    data4: [173, 158, 109, 95, 143, 167, 196, 59],
};
pub type MF_EVENT_TYPE = i32;
pub const MEUnknown: MF_EVENT_TYPE = 0i32;
pub const MEError: MF_EVENT_TYPE = 1i32;
pub const MEExtendedType: MF_EVENT_TYPE = 2i32;
pub const MENonFatalError: MF_EVENT_TYPE = 3i32;
pub const MEGenericV1Anchor: MF_EVENT_TYPE = 3i32;
pub const MESessionUnknown: MF_EVENT_TYPE = 100i32;
pub const MESessionTopologySet: MF_EVENT_TYPE = 101i32;
pub const MESessionTopologiesCleared: MF_EVENT_TYPE = 102i32;
pub const MESessionStarted: MF_EVENT_TYPE = 103i32;
pub const MESessionPaused: MF_EVENT_TYPE = 104i32;
pub const MESessionStopped: MF_EVENT_TYPE = 105i32;
pub const MESessionClosed: MF_EVENT_TYPE = 106i32;
pub const MESessionEnded: MF_EVENT_TYPE = 107i32;
pub const MESessionRateChanged: MF_EVENT_TYPE = 108i32;
pub const MESessionScrubSampleComplete: MF_EVENT_TYPE = 109i32;
pub const MESessionCapabilitiesChanged: MF_EVENT_TYPE = 110i32;
pub const MESessionTopologyStatus: MF_EVENT_TYPE = 111i32;
pub const MESessionNotifyPresentationTime: MF_EVENT_TYPE = 112i32;
pub const MENewPresentation: MF_EVENT_TYPE = 113i32;
pub const MELicenseAcquisitionStart: MF_EVENT_TYPE = 114i32;
pub const MELicenseAcquisitionCompleted: MF_EVENT_TYPE = 115i32;
pub const MEIndividualizationStart: MF_EVENT_TYPE = 116i32;
pub const MEIndividualizationCompleted: MF_EVENT_TYPE = 117i32;
pub const MEEnablerProgress: MF_EVENT_TYPE = 118i32;
pub const MEEnablerCompleted: MF_EVENT_TYPE = 119i32;
pub const MEPolicyError: MF_EVENT_TYPE = 120i32;
pub const MEPolicyReport: MF_EVENT_TYPE = 121i32;
pub const MEBufferingStarted: MF_EVENT_TYPE = 122i32;
pub const MEBufferingStopped: MF_EVENT_TYPE = 123i32;
pub const MEConnectStart: MF_EVENT_TYPE = 124i32;
pub const MEConnectEnd: MF_EVENT_TYPE = 125i32;
pub const MEReconnectStart: MF_EVENT_TYPE = 126i32;
pub const MEReconnectEnd: MF_EVENT_TYPE = 127i32;
pub const MERendererEvent: MF_EVENT_TYPE = 128i32;
pub const MESessionStreamSinkFormatChanged: MF_EVENT_TYPE = 129i32;
pub const MESessionV1Anchor: MF_EVENT_TYPE = 129i32;
pub const MESourceUnknown: MF_EVENT_TYPE = 200i32;
pub const MESourceStarted: MF_EVENT_TYPE = 201i32;
pub const MEStreamStarted: MF_EVENT_TYPE = 202i32;
pub const MESourceSeeked: MF_EVENT_TYPE = 203i32;
pub const MEStreamSeeked: MF_EVENT_TYPE = 204i32;
pub const MENewStream: MF_EVENT_TYPE = 205i32;
pub const MEUpdatedStream: MF_EVENT_TYPE = 206i32;
pub const MESourceStopped: MF_EVENT_TYPE = 207i32;
pub const MEStreamStopped: MF_EVENT_TYPE = 208i32;
pub const MESourcePaused: MF_EVENT_TYPE = 209i32;
pub const MEStreamPaused: MF_EVENT_TYPE = 210i32;
pub const MEEndOfPresentation: MF_EVENT_TYPE = 211i32;
pub const MEEndOfStream: MF_EVENT_TYPE = 212i32;
pub const MEMediaSample: MF_EVENT_TYPE = 213i32;
pub const MEStreamTick: MF_EVENT_TYPE = 214i32;
pub const MEStreamThinMode: MF_EVENT_TYPE = 215i32;
pub const MEStreamFormatChanged: MF_EVENT_TYPE = 216i32;
pub const MESourceRateChanged: MF_EVENT_TYPE = 217i32;
pub const MEEndOfPresentationSegment: MF_EVENT_TYPE = 218i32;
pub const MESourceCharacteristicsChanged: MF_EVENT_TYPE = 219i32;
pub const MESourceRateChangeRequested: MF_EVENT_TYPE = 220i32;
pub const MESourceMetadataChanged: MF_EVENT_TYPE = 221i32;
pub const MESequencerSourceTopologyUpdated: MF_EVENT_TYPE = 222i32;
pub const MESourceV1Anchor: MF_EVENT_TYPE = 222i32;
pub const MESinkUnknown: MF_EVENT_TYPE = 300i32;
pub const MEStreamSinkStarted: MF_EVENT_TYPE = 301i32;
pub const MEStreamSinkStopped: MF_EVENT_TYPE = 302i32;
pub const MEStreamSinkPaused: MF_EVENT_TYPE = 303i32;
pub const MEStreamSinkRateChanged: MF_EVENT_TYPE = 304i32;
pub const MEStreamSinkRequestSample: MF_EVENT_TYPE = 305i32;
pub const MEStreamSinkMarker: MF_EVENT_TYPE = 306i32;
pub const MEStreamSinkPrerolled: MF_EVENT_TYPE = 307i32;
pub const MEStreamSinkScrubSampleComplete: MF_EVENT_TYPE = 308i32;
pub const MEStreamSinkFormatChanged: MF_EVENT_TYPE = 309i32;
pub const MEStreamSinkDeviceChanged: MF_EVENT_TYPE = 310i32;
pub const MEQualityNotify: MF_EVENT_TYPE = 311i32;
pub const MESinkInvalidated: MF_EVENT_TYPE = 312i32;
pub const MEAudioSessionNameChanged: MF_EVENT_TYPE = 313i32;
pub const MEAudioSessionVolumeChanged: MF_EVENT_TYPE = 314i32;
pub const MEAudioSessionDeviceRemoved: MF_EVENT_TYPE = 315i32;
pub const MEAudioSessionServerShutdown: MF_EVENT_TYPE = 316i32;
pub const MEAudioSessionGroupingParamChanged: MF_EVENT_TYPE = 317i32;
pub const MEAudioSessionIconChanged: MF_EVENT_TYPE = 318i32;
pub const MEAudioSessionFormatChanged: MF_EVENT_TYPE = 319i32;
pub const MEAudioSessionDisconnected: MF_EVENT_TYPE = 320i32;
pub const MEAudioSessionExclusiveModeOverride: MF_EVENT_TYPE = 321i32;
pub const MESinkV1Anchor: MF_EVENT_TYPE = 321i32;
pub const MECaptureAudioSessionVolumeChanged: MF_EVENT_TYPE = 322i32;
pub const MECaptureAudioSessionDeviceRemoved: MF_EVENT_TYPE = 323i32;
pub const MECaptureAudioSessionFormatChanged: MF_EVENT_TYPE = 324i32;
pub const MECaptureAudioSessionDisconnected: MF_EVENT_TYPE = 325i32;
pub const MECaptureAudioSessionExclusiveModeOverride: MF_EVENT_TYPE = 326i32;
pub const MECaptureAudioSessionServerShutdown: MF_EVENT_TYPE = 327i32;
pub const MESinkV2Anchor: MF_EVENT_TYPE = 327i32;
pub const METrustUnknown: MF_EVENT_TYPE = 400i32;
pub const MEPolicyChanged: MF_EVENT_TYPE = 401i32;
pub const MEContentProtectionMessage: MF_EVENT_TYPE = 402i32;
pub const MEPolicySet: MF_EVENT_TYPE = 403i32;
pub const METrustV1Anchor: MF_EVENT_TYPE = 403i32;
pub const MEWMDRMLicenseBackupCompleted: MF_EVENT_TYPE = 500i32;
pub const MEWMDRMLicenseBackupProgress: MF_EVENT_TYPE = 501i32;
pub const MEWMDRMLicenseRestoreCompleted: MF_EVENT_TYPE = 502i32;
pub const MEWMDRMLicenseRestoreProgress: MF_EVENT_TYPE = 503i32;
pub const MEWMDRMLicenseAcquisitionCompleted: MF_EVENT_TYPE = 506i32;
pub const MEWMDRMIndividualizationCompleted: MF_EVENT_TYPE = 508i32;
pub const MEWMDRMIndividualizationProgress: MF_EVENT_TYPE = 513i32;
pub const MEWMDRMProximityCompleted: MF_EVENT_TYPE = 514i32;
pub const MEWMDRMLicenseStoreCleaned: MF_EVENT_TYPE = 515i32;
pub const MEWMDRMRevocationDownloadCompleted: MF_EVENT_TYPE = 516i32;
pub const MEWMDRMV1Anchor: MF_EVENT_TYPE = 516i32;
pub const METransformUnknown: MF_EVENT_TYPE = 600i32;
pub const METransformNeedInput: MF_EVENT_TYPE = 601i32;
pub const METransformHaveOutput: MF_EVENT_TYPE = 602i32;
pub const METransformDrainComplete: MF_EVENT_TYPE = 603i32;
pub const METransformMarker: MF_EVENT_TYPE = 604i32;
pub const METransformInputStreamStateChanged: MF_EVENT_TYPE = 605i32;
pub const MEByteStreamCharacteristicsChanged: MF_EVENT_TYPE = 700i32;
pub const MEVideoCaptureDeviceRemoved: MF_EVENT_TYPE = 800i32;
pub const MEVideoCaptureDevicePreempted: MF_EVENT_TYPE = 801i32;
pub const MEStreamSinkFormatInvalidated: MF_EVENT_TYPE = 802i32;
pub const MEEncodingParameters: MF_EVENT_TYPE = 803i32;
pub const MEContentProtectionMetadata: MF_EVENT_TYPE = 900i32;
pub const MEDeviceThermalStateChanged: MF_EVENT_TYPE = 950i32;
pub const MEReservedMax: MF_EVENT_TYPE = 10000i32;
pub const MF_E_ALLOCATOR_ALREADY_COMMITED: ::windows_sys::core::HRESULT = -1072846854i32;
pub const MF_E_ALLOCATOR_NOT_COMMITED: ::windows_sys::core::HRESULT = -1072846855i32;
pub const MF_E_ALLOCATOR_NOT_INITIALIZED: ::windows_sys::core::HRESULT = -1072846856i32;
pub const MF_E_ALL_PROCESS_RESTART_REQUIRED: ::windows_sys::core::HRESULT = -1072860820i32;
pub const MF_E_ALREADY_INITIALIZED: ::windows_sys::core::HRESULT = -1072871856i32;
pub const MF_E_ASF_DROPPED_PACKET: ::windows_sys::core::HRESULT = -1072874847i32;
pub const MF_E_ASF_FILESINK_BITRATE_UNKNOWN: ::windows_sys::core::HRESULT = -1072870848i32;
pub const MF_E_ASF_INDEXNOTLOADED: ::windows_sys::core::HRESULT = -1072874850i32;
pub const MF_E_ASF_INVALIDDATA: ::windows_sys::core::HRESULT = -1072874854i32;
pub const MF_E_ASF_MISSINGDATA: ::windows_sys::core::HRESULT = -1072874855i32;
pub const MF_E_ASF_NOINDEX: ::windows_sys::core::HRESULT = -1072874852i32;
pub const MF_E_ASF_OPAQUEPACKET: ::windows_sys::core::HRESULT = -1072874853i32;
pub const MF_E_ASF_OUTOFRANGE: ::windows_sys::core::HRESULT = -1072874851i32;
pub const MF_E_ASF_PARSINGINCOMPLETE: ::windows_sys::core::HRESULT = -1072874856i32;
pub const MF_E_ASF_TOO_MANY_PAYLOADS: ::windows_sys::core::HRESULT = -1072874849i32;
pub const MF_E_ASF_UNSUPPORTED_STREAM_TYPE: ::windows_sys::core::HRESULT = -1072874848i32;
pub const MF_E_ATTRIBUTENOTFOUND: ::windows_sys::core::HRESULT = -1072875802i32;
pub const MF_E_AUDIO_BUFFER_SIZE_ERROR: ::windows_sys::core::HRESULT = -1072869752i32;
pub const MF_E_AUDIO_CLIENT_WRAPPER_SPOOF_ERROR: ::windows_sys::core::HRESULT = -1072869751i32;
pub const MF_E_AUDIO_PLAYBACK_DEVICE_INVALIDATED: ::windows_sys::core::HRESULT = -1072869754i32;
pub const MF_E_AUDIO_PLAYBACK_DEVICE_IN_USE: ::windows_sys::core::HRESULT = -1072869755i32;
pub const MF_E_AUDIO_RECORDING_DEVICE_INVALIDATED: ::windows_sys::core::HRESULT = -1072873823i32;
pub const MF_E_AUDIO_RECORDING_DEVICE_IN_USE: ::windows_sys::core::HRESULT = -1072873824i32;
pub const MF_E_AUDIO_SERVICE_NOT_RUNNING: ::windows_sys::core::HRESULT = -1072869753i32;
pub const MF_E_BACKUP_RESTRICTED_LICENSE: ::windows_sys::core::HRESULT = -1072860850i32;
pub const MF_E_BAD_OPL_STRUCTURE_FORMAT: ::windows_sys::core::HRESULT = -1072860803i32;
pub const MF_E_BAD_STARTUP_VERSION: ::windows_sys::core::HRESULT = -1072875805i32;
pub const MF_E_BANDWIDTH_OVERRUN: ::windows_sys::core::HRESULT = -1072871855i32;
pub const MF_E_BUFFERTOOSMALL: ::windows_sys::core::HRESULT = -1072875855i32;
pub const MF_E_BYTESTREAM_NOT_SEEKABLE: ::windows_sys::core::HRESULT = -1072875794i32;
pub const MF_E_BYTESTREAM_UNKNOWN_LENGTH: ::windows_sys::core::HRESULT = -1072875781i32;
pub const MF_E_CANNOT_CREATE_SINK: ::windows_sys::core::HRESULT = -1072875782i32;
pub const MF_E_CANNOT_FIND_KEYFRAME_SAMPLE: ::windows_sys::core::HRESULT = -1072873827i32;
pub const MF_E_CANNOT_INDEX_IN_PLACE: ::windows_sys::core::HRESULT = -1072871849i32;
pub const MF_E_CANNOT_PARSE_BYTESTREAM: ::windows_sys::core::HRESULT = -1072875792i32;
pub const MF_E_CAPTURE_ENGINE_ALL_EFFECTS_REMOVED: ::windows_sys::core::HRESULT = -1072845851i32;
pub const MF_E_CAPTURE_ENGINE_INVALID_OP: ::windows_sys::core::HRESULT = -1072845852i32;
pub const MF_E_CAPTURE_NO_SAMPLES_IN_QUEUE: ::windows_sys::core::HRESULT = -1072845845i32;
pub const MF_E_CAPTURE_PROPERTY_SET_DURING_PHOTO: ::windows_sys::core::HRESULT = -1072845846i32;
pub const MF_E_CAPTURE_SINK_MIRROR_ERROR: ::windows_sys::core::HRESULT = -1072845854i32;
pub const MF_E_CAPTURE_SINK_OUTPUT_NOT_SET: ::windows_sys::core::HRESULT = -1072845855i32;
pub const MF_E_CAPTURE_SINK_ROTATE_ERROR: ::windows_sys::core::HRESULT = -1072845853i32;
pub const MF_E_CAPTURE_SOURCE_DEVICE_EXTENDEDPROP_OP_IN_PROGRESS: ::windows_sys::core::HRESULT = -1072845847i32;
pub const MF_E_CAPTURE_SOURCE_NO_AUDIO_STREAM_PRESENT: ::windows_sys::core::HRESULT = -1072845848i32;
pub const MF_E_CAPTURE_SOURCE_NO_INDEPENDENT_PHOTO_STREAM_PRESENT: ::windows_sys::core::HRESULT = -1072845850i32;
pub const MF_E_CAPTURE_SOURCE_NO_VIDEO_STREAM_PRESENT: ::windows_sys::core::HRESULT = -1072845849i32;
pub const MF_E_CLOCK_AUDIO_DEVICE_POSITION_UNEXPECTED: ::windows_sys::core::HRESULT = 891973i32;
pub const MF_E_CLOCK_AUDIO_RENDER_POSITION_UNEXPECTED: ::windows_sys::core::HRESULT = 891974i32;
pub const MF_E_CLOCK_AUDIO_RENDER_TIME_UNEXPECTED: ::windows_sys::core::HRESULT = 891975i32;
pub const MF_E_CLOCK_INVALID_CONTINUITY_KEY: ::windows_sys::core::HRESULT = -1072849856i32;
pub const MF_E_CLOCK_NOT_SIMPLE: ::windows_sys::core::HRESULT = -1072849853i32;
pub const MF_E_CLOCK_NO_TIME_SOURCE: ::windows_sys::core::HRESULT = -1072849855i32;
pub const MF_E_CLOCK_STATE_ALREADY_SET: ::windows_sys::core::HRESULT = -1072849854i32;
pub const MF_E_CODE_EXPIRED: ::windows_sys::core::HRESULT = -1072860834i32;
pub const MF_E_COMPONENT_REVOKED: ::windows_sys::core::HRESULT = -1072860847i32;
pub const MF_E_CONTENT_PROTECTION_SYSTEM_NOT_ENABLED: ::windows_sys::core::HRESULT = -1072860795i32;
pub const MF_E_DEBUGGING_NOT_ALLOWED: ::windows_sys::core::HRESULT = -1072860835i32;
pub const MF_E_DISABLED_IN_SAFEMODE: ::windows_sys::core::HRESULT = -1072875793i32;
pub const MF_E_DRM_HARDWARE_INCONSISTENT: ::windows_sys::core::HRESULT = -1072860853i32;
pub const MF_E_DRM_MIGRATION_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072860793i32;
pub const MF_E_DRM_UNSUPPORTED: ::windows_sys::core::HRESULT = -1072875776i32;
pub const MF_E_DROPTIME_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072848854i32;
pub const MF_E_DURATION_TOO_LONG: ::windows_sys::core::HRESULT = -1072875769i32;
pub const MF_E_DXGI_DEVICE_NOT_INITIALIZED: ::windows_sys::core::HRESULT = -2147217408i32;
pub const MF_E_DXGI_NEW_VIDEO_DEVICE: ::windows_sys::core::HRESULT = -2147217407i32;
pub const MF_E_DXGI_VIDEO_DEVICE_LOCKED: ::windows_sys::core::HRESULT = -2147217406i32;
pub const MF_E_END_OF_STREAM: ::windows_sys::core::HRESULT = -1072873852i32;
pub const MF_E_FLUSH_NEEDED: ::windows_sys::core::HRESULT = -1072871853i32;
pub const MF_E_FORMAT_CHANGE_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072875778i32;
pub const MF_E_GRL_ABSENT: ::windows_sys::core::HRESULT = -1072860814i32;
pub const MF_E_GRL_EXTENSIBLE_ENTRY_NOT_FOUND: ::windows_sys::core::HRESULT = -1072860831i32;
pub const MF_E_GRL_INVALID_FORMAT: ::windows_sys::core::HRESULT = -1072860822i32;
pub const MF_E_GRL_RENEWAL_NOT_FOUND: ::windows_sys::core::HRESULT = -1072860832i32;
pub const MF_E_GRL_UNRECOGNIZED_FORMAT: ::windows_sys::core::HRESULT = -1072860821i32;
pub const MF_E_GRL_VERSION_TOO_LOW: ::windows_sys::core::HRESULT = -1072860833i32;
pub const MF_E_HARDWARE_DRM_UNSUPPORTED: ::windows_sys::core::HRESULT = -1072875770i32;
pub const MF_E_HDCP_AUTHENTICATION_FAILURE: ::windows_sys::core::HRESULT = -1072860792i32;
pub const MF_E_HDCP_LINK_FAILURE: ::windows_sys::core::HRESULT = -1072860791i32;
pub const MF_E_HIGH_SECURITY_LEVEL_CONTENT_NOT_ALLOWED: ::windows_sys::core::HRESULT = -1072860808i32;
pub const MF_E_HW_ACCELERATED_THUMBNAIL_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072845844i32;
pub const MF_E_HW_MFT_FAILED_START_STREAMING: ::windows_sys::core::HRESULT = -1072875772i32;
pub const MF_E_HW_STREAM_NOT_CONNECTED: ::windows_sys::core::HRESULT = -1072846851i32;
pub const MF_E_INCOMPATIBLE_SAMPLE_PROTECTION: ::windows_sys::core::HRESULT = -1072860810i32;
pub const MF_E_INDEX_NOT_COMMITTED: ::windows_sys::core::HRESULT = -1072871851i32;
pub const MF_E_INSUFFICIENT_BUFFER: ::windows_sys::core::HRESULT = -1072860816i32;
pub const MF_E_INVALIDINDEX: ::windows_sys::core::HRESULT = -1072875841i32;
pub const MF_E_INVALIDMEDIATYPE: ::windows_sys::core::HRESULT = -1072875852i32;
pub const MF_E_INVALIDNAME: ::windows_sys::core::HRESULT = -1072875844i32;
pub const MF_E_INVALIDREQUEST: ::windows_sys::core::HRESULT = -1072875854i32;
pub const MF_E_INVALIDSTREAMNUMBER: ::windows_sys::core::HRESULT = -1072875853i32;
pub const MF_E_INVALIDTYPE: ::windows_sys::core::HRESULT = -1072875843i32;
pub const MF_E_INVALID_AKE_CHANNEL_PARAMETERS: ::windows_sys::core::HRESULT = -1072860796i32;
pub const MF_E_INVALID_ASF_STREAMID: ::windows_sys::core::HRESULT = -1072871847i32;
pub const MF_E_INVALID_CODEC_MERIT: ::windows_sys::core::HRESULT = -1072875773i32;
pub const MF_E_INVALID_FILE_FORMAT: ::windows_sys::core::HRESULT = -1072875842i32;
pub const MF_E_INVALID_FORMAT: ::windows_sys::core::HRESULT = -1072873844i32;
pub const MF_E_INVALID_KEY: ::windows_sys::core::HRESULT = -1072875806i32;
pub const MF_E_INVALID_POSITION: ::windows_sys::core::HRESULT = -1072875803i32;
pub const MF_E_INVALID_PROFILE: ::windows_sys::core::HRESULT = -1072871852i32;
pub const MF_E_INVALID_STATE_TRANSITION: ::windows_sys::core::HRESULT = -1072873854i32;
pub const MF_E_INVALID_STREAM_DATA: ::windows_sys::core::HRESULT = -1072875829i32;
pub const MF_E_INVALID_STREAM_STATE: ::windows_sys::core::HRESULT = -1072846852i32;
pub const MF_E_INVALID_TIMESTAMP: ::windows_sys::core::HRESULT = -1072875840i32;
pub const MF_E_INVALID_WORKQUEUE: ::windows_sys::core::HRESULT = -1072875777i32;
pub const MF_E_ITA_ERROR_PARSING_SAP_PARAMETERS: ::windows_sys::core::HRESULT = -1072860805i32;
pub const MF_E_ITA_OPL_DATA_NOT_INITIALIZED: ::windows_sys::core::HRESULT = -1072860800i32;
pub const MF_E_ITA_UNRECOGNIZED_ANALOG_VIDEO_OUTPUT: ::windows_sys::core::HRESULT = -1072860799i32;
pub const MF_E_ITA_UNRECOGNIZED_ANALOG_VIDEO_PROTECTION_GUID: ::windows_sys::core::HRESULT = -1072860802i32;
pub const MF_E_ITA_UNRECOGNIZED_DIGITAL_VIDEO_OUTPUT: ::windows_sys::core::HRESULT = -1072860798i32;
pub const MF_E_ITA_UNSUPPORTED_ACTION: ::windows_sys::core::HRESULT = -1072860806i32;
pub const MF_E_KERNEL_UNTRUSTED: ::windows_sys::core::HRESULT = -1072860830i32;
pub const MF_E_LATE_SAMPLE: ::windows_sys::core::HRESULT = -1072871854i32;
pub const MF_E_LICENSE_INCORRECT_RIGHTS: ::windows_sys::core::HRESULT = -1072860856i32;
pub const MF_E_LICENSE_OUTOFDATE: ::windows_sys::core::HRESULT = -1072860855i32;
pub const MF_E_LICENSE_REQUIRED: ::windows_sys::core::HRESULT = -1072860854i32;
pub const MF_E_LICENSE_RESTORE_NEEDS_INDIVIDUALIZATION: ::windows_sys::core::HRESULT = -1072860849i32;
pub const MF_E_LICENSE_RESTORE_NO_RIGHTS: ::windows_sys::core::HRESULT = -1072860851i32;
pub const MF_E_MEDIAPROC_WRONGSTATE: ::windows_sys::core::HRESULT = -1072875790i32;
pub const MF_E_MEDIA_EXTENSION_APPSERVICE_CONNECTION_FAILED: ::windows_sys::core::HRESULT = -1072843856i32;
pub const MF_E_MEDIA_EXTENSION_APPSERVICE_REQUEST_FAILED: ::windows_sys::core::HRESULT = -1072843855i32;
pub const MF_E_MEDIA_EXTENSION_PACKAGE_INTEGRITY_CHECK_FAILED: ::windows_sys::core::HRESULT = -1072843854i32;
pub const MF_E_MEDIA_EXTENSION_PACKAGE_LICENSE_INVALID: ::windows_sys::core::HRESULT = -1072843853i32;
pub const MF_E_MEDIA_SOURCE_NOT_STARTED: ::windows_sys::core::HRESULT = -1072873839i32;
pub const MF_E_MEDIA_SOURCE_NO_STREAMS_SELECTED: ::windows_sys::core::HRESULT = -1072873828i32;
pub const MF_E_MEDIA_SOURCE_WRONGSTATE: ::windows_sys::core::HRESULT = -1072873829i32;
pub const MF_E_METADATA_TOO_LONG: ::windows_sys::core::HRESULT = -1072870845i32;
pub const MF_E_MISSING_ASF_LEAKYBUCKET: ::windows_sys::core::HRESULT = -1072871848i32;
pub const MF_E_MP3_BAD_CRC: ::windows_sys::core::HRESULT = -1072873831i32;
pub const MF_E_MP3_NOTFOUND: ::windows_sys::core::HRESULT = -1072873850i32;
pub const MF_E_MP3_NOTMP3: ::windows_sys::core::HRESULT = -1072873848i32;
pub const MF_E_MP3_NOTSUPPORTED: ::windows_sys::core::HRESULT = -1072873847i32;
pub const MF_E_MP3_OUTOFDATA: ::windows_sys::core::HRESULT = -1072873849i32;
pub const MF_E_MULTIPLE_BEGIN: ::windows_sys::core::HRESULT = -1072875815i32;
pub const MF_E_MULTIPLE_SUBSCRIBERS: ::windows_sys::core::HRESULT = -1072875814i32;
pub const MF_E_NETWORK_RESOURCE_FAILURE: ::windows_sys::core::HRESULT = -1072872856i32;
pub const MF_E_NET_BAD_CONTROL_DATA: ::windows_sys::core::HRESULT = -1072872838i32;
pub const MF_E_NET_BAD_REQUEST: ::windows_sys::core::HRESULT = -1072872833i32;
pub const MF_E_NET_BUSY: ::windows_sys::core::HRESULT = -1072872822i32;
pub const MF_E_NET_BWLEVEL_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072872851i32;
pub const MF_E_NET_CACHESTREAM_NOT_FOUND: ::windows_sys::core::HRESULT = -1072872847i32;
pub const MF_E_NET_CACHE_NO_DATA: ::windows_sys::core::HRESULT = -1072872835i32;
pub const MF_E_NET_CANNOTCONNECT: ::windows_sys::core::HRESULT = -1072872825i32;
pub const MF_E_NET_CLIENT_CLOSE: ::windows_sys::core::HRESULT = -1072872839i32;
pub const MF_E_NET_COMPANION_DRIVER_DISCONNECT: ::windows_sys::core::HRESULT = -1072872811i32;
pub const MF_E_NET_CONNECTION_FAILURE: ::windows_sys::core::HRESULT = -1072872829i32;
pub const MF_E_NET_EOL: ::windows_sys::core::HRESULT = -1072872834i32;
pub const MF_E_NET_ERROR_FROM_PROXY: ::windows_sys::core::HRESULT = -1072872820i32;
pub const MF_E_NET_INCOMPATIBLE_PUSHSERVER: ::windows_sys::core::HRESULT = -1072872828i32;
pub const MF_E_NET_INCOMPATIBLE_SERVER: ::windows_sys::core::HRESULT = -1072872837i32;
pub const MF_E_NET_INTERNAL_SERVER_ERROR: ::windows_sys::core::HRESULT = -1072872832i32;
pub const MF_E_NET_INVALID_PRESENTATION_DESCRIPTOR: ::windows_sys::core::HRESULT = -1072872848i32;
pub const MF_E_NET_INVALID_PUSH_PUBLISHING_POINT: ::windows_sys::core::HRESULT = -1072872823i32;
pub const MF_E_NET_INVALID_PUSH_TEMPLATE: ::windows_sys::core::HRESULT = -1072872824i32;
pub const MF_E_NET_MANUALSS_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072872849i32;
pub const MF_E_NET_NOCONNECTION: ::windows_sys::core::HRESULT = -1072872830i32;
pub const MF_E_NET_PROTOCOL_DISABLED: ::windows_sys::core::HRESULT = -1072872812i32;
pub const MF_E_NET_PROXY_ACCESSDENIED: ::windows_sys::core::HRESULT = -1072872826i32;
pub const MF_E_NET_PROXY_TIMEOUT: ::windows_sys::core::HRESULT = -1072872819i32;
pub const MF_E_NET_READ: ::windows_sys::core::HRESULT = -1072872854i32;
pub const MF_E_NET_REDIRECT: ::windows_sys::core::HRESULT = -1072872843i32;
pub const MF_E_NET_REDIRECT_TO_PROXY: ::windows_sys::core::HRESULT = -1072872842i32;
pub const MF_E_NET_REQUIRE_ASYNC: ::windows_sys::core::HRESULT = -1072872852i32;
pub const MF_E_NET_REQUIRE_INPUT: ::windows_sys::core::HRESULT = -1072872844i32;
pub const MF_E_NET_REQUIRE_NETWORK: ::windows_sys::core::HRESULT = -1072872853i32;
pub const MF_E_NET_RESOURCE_GONE: ::windows_sys::core::HRESULT = -1072872821i32;
pub const MF_E_NET_SERVER_ACCESSDENIED: ::windows_sys::core::HRESULT = -1072872827i32;
pub const MF_E_NET_SERVER_UNAVAILABLE: ::windows_sys::core::HRESULT = -1072872818i32;
pub const MF_E_NET_SESSION_INVALID: ::windows_sys::core::HRESULT = -1072872816i32;
pub const MF_E_NET_SESSION_NOT_FOUND: ::windows_sys::core::HRESULT = -1072872831i32;
pub const MF_E_NET_STREAMGROUPS_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072872850i32;
pub const MF_E_NET_TIMEOUT: ::windows_sys::core::HRESULT = -1072872840i32;
pub const MF_E_NET_TOO_MANY_REDIRECTS: ::windows_sys::core::HRESULT = -1072872841i32;
pub const MF_E_NET_TOO_MUCH_DATA: ::windows_sys::core::HRESULT = -1072872817i32;
pub const MF_E_NET_UDP_BLOCKED: ::windows_sys::core::HRESULT = -1072872814i32;
pub const MF_E_NET_UNSAFE_URL: ::windows_sys::core::HRESULT = -1072872836i32;
pub const MF_E_NET_UNSUPPORTED_CONFIGURATION: ::windows_sys::core::HRESULT = -1072872813i32;
pub const MF_E_NET_WRITE: ::windows_sys::core::HRESULT = -1072872855i32;
pub const MF_E_NEW_VIDEO_DEVICE: ::windows_sys::core::HRESULT = -1072869851i32;
pub const MF_E_NON_PE_PROCESS: ::windows_sys::core::HRESULT = -1072860827i32;
pub const MF_E_NOTACCEPTING: ::windows_sys::core::HRESULT = -1072875851i32;
pub const MF_E_NOT_AVAILABLE: ::windows_sys::core::HRESULT = -1072875818i32;
pub const MF_E_NOT_FOUND: ::windows_sys::core::HRESULT = -1072875819i32;
pub const MF_E_NOT_INITIALIZED: ::windows_sys::core::HRESULT = -1072875850i32;
pub const MF_E_NOT_PROTECTED: ::windows_sys::core::HRESULT = -1072873830i32;
pub const MF_E_NO_AUDIO_PLAYBACK_DEVICE: ::windows_sys::core::HRESULT = -1072869756i32;
pub const MF_E_NO_AUDIO_RECORDING_DEVICE: ::windows_sys::core::HRESULT = -1072873825i32;
pub const MF_E_NO_BITPUMP: ::windows_sys::core::HRESULT = -1072875786i32;
pub const MF_E_NO_CAPTURE_DEVICES_AVAILABLE: ::windows_sys::core::HRESULT = -1072845856i32;
pub const MF_E_NO_CLOCK: ::windows_sys::core::HRESULT = -1072875817i32;
pub const MF_E_NO_CONTENT_PROTECTION_MANAGER: ::windows_sys::core::HRESULT = -1072860852i32;
pub const MF_E_NO_DURATION: ::windows_sys::core::HRESULT = -1072873846i32;
pub const MF_E_NO_EVENTS_AVAILABLE: ::windows_sys::core::HRESULT = -1072873856i32;
pub const MF_E_NO_INDEX: ::windows_sys::core::HRESULT = -1072871850i32;
pub const MF_E_NO_MORE_DROP_MODES: ::windows_sys::core::HRESULT = -1072848856i32;
pub const MF_E_NO_MORE_QUALITY_LEVELS: ::windows_sys::core::HRESULT = -1072848855i32;
pub const MF_E_NO_MORE_TYPES: ::windows_sys::core::HRESULT = -1072875847i32;
pub const MF_E_NO_PMP_HOST: ::windows_sys::core::HRESULT = -1072860801i32;
pub const MF_E_NO_SAMPLE_DURATION: ::windows_sys::core::HRESULT = -1072875831i32;
pub const MF_E_NO_SAMPLE_TIMESTAMP: ::windows_sys::core::HRESULT = -1072875832i32;
pub const MF_E_NO_SOURCE_IN_CACHE: ::windows_sys::core::HRESULT = -1072864850i32;
pub const MF_E_NO_VIDEO_SAMPLE_AVAILABLE: ::windows_sys::core::HRESULT = -1072869850i32;
pub const MF_E_OFFLINE_MODE: ::windows_sys::core::HRESULT = -1072872815i32;
pub const MF_E_OPERATION_CANCELLED: ::windows_sys::core::HRESULT = -1072875795i32;
pub const MF_E_OPERATION_IN_PROGRESS: ::windows_sys::core::HRESULT = -1072875771i32;
pub const MF_E_OPERATION_UNSUPPORTED_AT_D3D_FEATURE_LEVEL: ::windows_sys::core::HRESULT = -1072875768i32;
pub const MF_E_OPL_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072860838i32;
pub const MF_E_OUT_OF_RANGE: ::windows_sys::core::HRESULT = -1072875774i32;
pub const MF_E_PEAUTH_NOT_STARTED: ::windows_sys::core::HRESULT = -1072860811i32;
pub const MF_E_PEAUTH_PUBLICKEY_REVOKED: ::windows_sys::core::HRESULT = -1072860815i32;
pub const MF_E_PEAUTH_SESSION_NOT_STARTED: ::windows_sys::core::HRESULT = -1072860817i32;
pub const MF_E_PEAUTH_UNTRUSTED: ::windows_sys::core::HRESULT = -1072860829i32;
pub const MF_E_PE_SESSIONS_MAXED: ::windows_sys::core::HRESULT = -1072860809i32;
pub const MF_E_PE_UNTRUSTED: ::windows_sys::core::HRESULT = -1072860812i32;
pub const MF_E_PLATFORM_NOT_INITIALIZED: ::windows_sys::core::HRESULT = -1072875856i32;
pub const MF_E_POLICY_MGR_ACTION_OUTOFBOUNDS: ::windows_sys::core::HRESULT = -1072860804i32;
pub const MF_E_POLICY_UNSUPPORTED: ::windows_sys::core::HRESULT = -1072860839i32;
pub const MF_E_PROCESS_RESTART_REQUIRED: ::windows_sys::core::HRESULT = -1072860819i32;
pub const MF_E_PROPERTY_EMPTY: ::windows_sys::core::HRESULT = -1072875799i32;
pub const MF_E_PROPERTY_NOT_ALLOWED: ::windows_sys::core::HRESULT = -1072873841i32;
pub const MF_E_PROPERTY_NOT_EMPTY: ::windows_sys::core::HRESULT = -1072875798i32;
pub const MF_E_PROPERTY_NOT_FOUND: ::windows_sys::core::HRESULT = -1072873843i32;
pub const MF_E_PROPERTY_READ_ONLY: ::windows_sys::core::HRESULT = -1072873842i32;
pub const MF_E_PROPERTY_TYPE_NOT_ALLOWED: ::windows_sys::core::HRESULT = -1072875801i32;
pub const MF_E_PROPERTY_TYPE_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072875800i32;
pub const MF_E_PROPERTY_VECTOR_NOT_ALLOWED: ::windows_sys::core::HRESULT = -1072875797i32;
pub const MF_E_PROPERTY_VECTOR_REQUIRED: ::windows_sys::core::HRESULT = -1072875796i32;
pub const MF_E_QM_INVALIDSTATE: ::windows_sys::core::HRESULT = -1072848852i32;
pub const MF_E_QUALITYKNOB_WAIT_LONGER: ::windows_sys::core::HRESULT = -1072848853i32;
pub const MF_E_RATE_CHANGE_PREEMPTED: ::windows_sys::core::HRESULT = -1072875820i32;
pub const MF_E_REBOOT_REQUIRED: ::windows_sys::core::HRESULT = -1072860825i32;
pub const MF_E_RESOLUTION_REQUIRES_PMP_CREATION_CALLBACK: ::windows_sys::core::HRESULT = -1072860797i32;
pub const MF_E_REVERSE_UNSUPPORTED: ::windows_sys::core::HRESULT = -1072875822i32;
pub const MF_E_RT_OUTOFMEMORY: ::windows_sys::core::HRESULT = -1072875785i32;
pub const MF_E_RT_THROUGHPUT_NOT_AVAILABLE: ::windows_sys::core::HRESULT = -1072875789i32;
pub const MF_E_RT_TOO_MANY_CLASSES: ::windows_sys::core::HRESULT = -1072875788i32;
pub const MF_E_RT_UNAVAILABLE: ::windows_sys::core::HRESULT = -1072875825i32;
pub const MF_E_RT_WORKQUEUE_CLASS_NOT_SPECIFIED: ::windows_sys::core::HRESULT = -1072875784i32;
pub const MF_E_RT_WOULDBLOCK: ::windows_sys::core::HRESULT = -1072875787i32;
pub const MF_E_SAMPLEALLOCATOR_CANCELED: ::windows_sys::core::HRESULT = -1072870851i32;
pub const MF_E_SAMPLEALLOCATOR_EMPTY: ::windows_sys::core::HRESULT = -1072870850i32;
pub const MF_E_SAMPLE_HAS_TOO_MANY_BUFFERS: ::windows_sys::core::HRESULT = -1072875809i32;
pub const MF_E_SAMPLE_NOT_WRITABLE: ::windows_sys::core::HRESULT = -1072875808i32;
pub const MF_E_SEQUENCER_UNKNOWN_SEGMENT_ID: ::windows_sys::core::HRESULT = -1072864852i32;
pub const MF_E_SESSION_PAUSEWHILESTOPPED: ::windows_sys::core::HRESULT = -1072875780i32;
pub const MF_E_SHUTDOWN: ::windows_sys::core::HRESULT = -1072873851i32;
pub const MF_E_SIGNATURE_VERIFICATION_FAILED: ::windows_sys::core::HRESULT = -1072860836i32;
pub const MF_E_SINK_ALREADYSTOPPED: ::windows_sys::core::HRESULT = -1072870849i32;
pub const MF_E_SINK_HEADERS_NOT_FOUND: ::windows_sys::core::HRESULT = -1072870843i32;
pub const MF_E_SINK_NO_SAMPLES_PROCESSED: ::windows_sys::core::HRESULT = -1072870844i32;
pub const MF_E_SINK_NO_STREAMS: ::windows_sys::core::HRESULT = -1072870847i32;
pub const MF_E_SOURCERESOLVER_MUTUALLY_EXCLUSIVE_FLAGS: ::windows_sys::core::HRESULT = -1072875791i32;
pub const MF_E_STATE_TRANSITION_PENDING: ::windows_sys::core::HRESULT = -1072875812i32;
pub const MF_E_STREAMSINKS_FIXED: ::windows_sys::core::HRESULT = -1072870853i32;
pub const MF_E_STREAMSINKS_OUT_OF_SYNC: ::windows_sys::core::HRESULT = -1072870854i32;
pub const MF_E_STREAMSINK_EXISTS: ::windows_sys::core::HRESULT = -1072870852i32;
pub const MF_E_STREAMSINK_REMOVED: ::windows_sys::core::HRESULT = -1072870856i32;
pub const MF_E_STREAM_ERROR: ::windows_sys::core::HRESULT = -1072846853i32;
pub const MF_E_TEST_SIGNED_COMPONENTS_NOT_ALLOWED: ::windows_sys::core::HRESULT = -1072860807i32;
pub const MF_E_THINNING_UNSUPPORTED: ::windows_sys::core::HRESULT = -1072875823i32;
pub const MF_E_TIMELINECONTROLLER_CANNOT_ATTACH: ::windows_sys::core::HRESULT = -1072844854i32;
pub const MF_E_TIMELINECONTROLLER_NOT_ALLOWED: ::windows_sys::core::HRESULT = -1072844855i32;
pub const MF_E_TIMELINECONTROLLER_UNSUPPORTED_SOURCE_TYPE: ::windows_sys::core::HRESULT = -1072844856i32;
pub const MF_E_TIMER_ORPHANED: ::windows_sys::core::HRESULT = -1072875813i32;
pub const MF_E_TOPOLOGY_VERIFICATION_FAILED: ::windows_sys::core::HRESULT = -1072860837i32;
pub const MF_E_TOPO_CANNOT_CONNECT: ::windows_sys::core::HRESULT = -1072868845i32;
pub const MF_E_TOPO_CANNOT_FIND_DECRYPTOR: ::windows_sys::core::HRESULT = -1072868847i32;
pub const MF_E_TOPO_CODEC_NOT_FOUND: ::windows_sys::core::HRESULT = -1072868846i32;
pub const MF_E_TOPO_INVALID_OPTIONAL_NODE: ::windows_sys::core::HRESULT = -1072868850i32;
pub const MF_E_TOPO_INVALID_TIME_ATTRIBUTES: ::windows_sys::core::HRESULT = -1072868843i32;
pub const MF_E_TOPO_LOOPS_IN_TOPOLOGY: ::windows_sys::core::HRESULT = -1072868842i32;
pub const MF_E_TOPO_MISSING_PRESENTATION_DESCRIPTOR: ::windows_sys::core::HRESULT = -1072868841i32;
pub const MF_E_TOPO_MISSING_SOURCE: ::windows_sys::core::HRESULT = -1072868838i32;
pub const MF_E_TOPO_MISSING_STREAM_DESCRIPTOR: ::windows_sys::core::HRESULT = -1072868840i32;
pub const MF_E_TOPO_SINK_ACTIVATES_UNSUPPORTED: ::windows_sys::core::HRESULT = -1072868837i32;
pub const MF_E_TOPO_STREAM_DESCRIPTOR_NOT_SELECTED: ::windows_sys::core::HRESULT = -1072868839i32;
pub const MF_E_TOPO_UNSUPPORTED: ::windows_sys::core::HRESULT = -1072868844i32;
pub const MF_E_TRANSCODE_INVALID_PROFILE: ::windows_sys::core::HRESULT = -1072847853i32;
pub const MF_E_TRANSCODE_NO_CONTAINERTYPE: ::windows_sys::core::HRESULT = -1072847856i32;
pub const MF_E_TRANSCODE_NO_MATCHING_ENCODER: ::windows_sys::core::HRESULT = -1072847854i32;
pub const MF_E_TRANSCODE_PROFILE_NO_MATCHING_STREAMS: ::windows_sys::core::HRESULT = -1072847855i32;
pub const MF_E_TRANSFORM_ASYNC_LOCKED: ::windows_sys::core::HRESULT = -1072861833i32;
pub const MF_E_TRANSFORM_ASYNC_MFT_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072861830i32;
pub const MF_E_TRANSFORM_CANNOT_CHANGE_MEDIATYPE_WHILE_PROCESSING: ::windows_sys::core::HRESULT = -1072861836i32;
pub const MF_E_TRANSFORM_CANNOT_INITIALIZE_ACM_DRIVER: ::windows_sys::core::HRESULT = -1072861832i32;
pub const MF_E_TRANSFORM_CONFLICTS_WITH_OTHER_CURRENTLY_ENABLED_FEATURES: ::windows_sys::core::HRESULT = -1072861840i32;
pub const MF_E_TRANSFORM_EXATTRIBUTE_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072861828i32;
pub const MF_E_TRANSFORM_INPUT_REMAINING: ::windows_sys::core::HRESULT = -1072861854i32;
pub const MF_E_TRANSFORM_NEED_MORE_INPUT: ::windows_sys::core::HRESULT = -1072861838i32;
pub const MF_E_TRANSFORM_NOT_POSSIBLE_FOR_CURRENT_INPUT_MEDIATYPE: ::windows_sys::core::HRESULT = -1072861842i32;
pub const MF_E_TRANSFORM_NOT_POSSIBLE_FOR_CURRENT_MEDIATYPE_COMBINATION: ::windows_sys::core::HRESULT = -1072861841i32;
pub const MF_E_TRANSFORM_NOT_POSSIBLE_FOR_CURRENT_OUTPUT_MEDIATYPE: ::windows_sys::core::HRESULT = -1072861843i32;
pub const MF_E_TRANSFORM_NOT_POSSIBLE_FOR_CURRENT_SPKR_CONFIG: ::windows_sys::core::HRESULT = -1072861837i32;
pub const MF_E_TRANSFORM_PROFILE_INVALID_OR_CORRUPT: ::windows_sys::core::HRESULT = -1072861852i32;
pub const MF_E_TRANSFORM_PROFILE_MISSING: ::windows_sys::core::HRESULT = -1072861853i32;
pub const MF_E_TRANSFORM_PROFILE_TRUNCATED: ::windows_sys::core::HRESULT = -1072861851i32;
pub const MF_E_TRANSFORM_PROPERTY_ARRAY_VALUE_WRONG_NUM_DIM: ::windows_sys::core::HRESULT = -1072861847i32;
pub const MF_E_TRANSFORM_PROPERTY_NOT_WRITEABLE: ::windows_sys::core::HRESULT = -1072861848i32;
pub const MF_E_TRANSFORM_PROPERTY_PID_NOT_RECOGNIZED: ::windows_sys::core::HRESULT = -1072861850i32;
pub const MF_E_TRANSFORM_PROPERTY_VALUE_INCOMPATIBLE: ::windows_sys::core::HRESULT = -1072861844i32;
pub const MF_E_TRANSFORM_PROPERTY_VALUE_OUT_OF_RANGE: ::windows_sys::core::HRESULT = -1072861845i32;
pub const MF_E_TRANSFORM_PROPERTY_VALUE_SIZE_WRONG: ::windows_sys::core::HRESULT = -1072861846i32;
pub const MF_E_TRANSFORM_PROPERTY_VARIANT_TYPE_WRONG: ::windows_sys::core::HRESULT = -1072861849i32;
pub const MF_E_TRANSFORM_STREAM_CHANGE: ::windows_sys::core::HRESULT = -1072861855i32;
pub const MF_E_TRANSFORM_STREAM_INVALID_RESOLUTION: ::windows_sys::core::HRESULT = -1072861831i32;
pub const MF_E_TRANSFORM_TYPE_NOT_SET: ::windows_sys::core::HRESULT = -1072861856i32;
pub const MF_E_TRUST_DISABLED: ::windows_sys::core::HRESULT = -1072860846i32;
pub const MF_E_UNAUTHORIZED: ::windows_sys::core::HRESULT = -1072875775i32;
pub const MF_E_UNEXPECTED: ::windows_sys::core::HRESULT = -1072875845i32;
pub const MF_E_UNRECOVERABLE_ERROR_OCCURRED: ::windows_sys::core::HRESULT = -1072875810i32;
pub const MF_E_UNSUPPORTED_BYTESTREAM_TYPE: ::windows_sys::core::HRESULT = -1072875836i32;
pub const MF_E_UNSUPPORTED_CAPTION: ::windows_sys::core::HRESULT = -1072875804i32;
pub const MF_E_UNSUPPORTED_CAPTURE_DEVICE_PRESENT: ::windows_sys::core::HRESULT = -1072845843i32;
pub const MF_E_UNSUPPORTED_CHARACTERISTICS: ::windows_sys::core::HRESULT = -1072873826i32;
pub const MF_E_UNSUPPORTED_CONTENT_PROTECTION_SYSTEM: ::windows_sys::core::HRESULT = -1072860794i32;
pub const MF_E_UNSUPPORTED_D3D_TYPE: ::windows_sys::core::HRESULT = -1072861834i32;
pub const MF_E_UNSUPPORTED_FORMAT: ::windows_sys::core::HRESULT = -1072873832i32;
pub const MF_E_UNSUPPORTED_MEDIATYPE_AT_D3D_FEATURE_LEVEL: ::windows_sys::core::HRESULT = -1072875767i32;
pub const MF_E_UNSUPPORTED_RATE: ::windows_sys::core::HRESULT = -1072875824i32;
pub const MF_E_UNSUPPORTED_RATE_TRANSITION: ::windows_sys::core::HRESULT = -1072875821i32;
pub const MF_E_UNSUPPORTED_REPRESENTATION: ::windows_sys::core::HRESULT = -1072875849i32;
pub const MF_E_UNSUPPORTED_SCHEME: ::windows_sys::core::HRESULT = -1072875837i32;
pub const MF_E_UNSUPPORTED_SERVICE: ::windows_sys::core::HRESULT = -1072875846i32;
pub const MF_E_UNSUPPORTED_STATE_TRANSITION: ::windows_sys::core::HRESULT = -1072875811i32;
pub const MF_E_UNSUPPORTED_TIME_FORMAT: ::windows_sys::core::HRESULT = -1072875835i32;
pub const MF_E_USERMODE_UNTRUSTED: ::windows_sys::core::HRESULT = -1072860818i32;
pub const MF_E_VIDEO_DEVICE_LOCKED: ::windows_sys::core::HRESULT = -1072869852i32;
pub const MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED: ::windows_sys::core::HRESULT = -1072873822i32;
pub const MF_E_VIDEO_RECORDING_DEVICE_PREEMPTED: ::windows_sys::core::HRESULT = -1072873821i32;
pub const MF_E_VIDEO_REN_COPYPROT_FAILED: ::windows_sys::core::HRESULT = -1072869854i32;
pub const MF_E_VIDEO_REN_NO_DEINTERLACE_HW: ::windows_sys::core::HRESULT = -1072869855i32;
pub const MF_E_VIDEO_REN_NO_PROCAMP_HW: ::windows_sys::core::HRESULT = -1072869856i32;
pub const MF_E_VIDEO_REN_SURFACE_NOT_SHARED: ::windows_sys::core::HRESULT = -1072869853i32;
pub const MF_E_WMDRMOTA_ACTION_ALREADY_SET: ::windows_sys::core::HRESULT = -1072860844i32;
pub const MF_E_WMDRMOTA_ACTION_MISMATCH: ::windows_sys::core::HRESULT = -1072860841i32;
pub const MF_E_WMDRMOTA_DRM_ENCRYPTION_SCHEME_NOT_SUPPORTED: ::windows_sys::core::HRESULT = -1072860842i32;
pub const MF_E_WMDRMOTA_DRM_HEADER_NOT_AVAILABLE: ::windows_sys::core::HRESULT = -1072860843i32;
pub const MF_E_WMDRMOTA_INVALID_POLICY: ::windows_sys::core::HRESULT = -1072860840i32;
pub const MF_E_WMDRMOTA_NO_ACTION: ::windows_sys::core::HRESULT = -1072860845i32;
pub type MF_FILE_ACCESSMODE = i32;
pub const MF_ACCESSMODE_READ: MF_FILE_ACCESSMODE = 1i32;
pub const MF_ACCESSMODE_WRITE: MF_FILE_ACCESSMODE = 2i32;
pub const MF_ACCESSMODE_READWRITE: MF_FILE_ACCESSMODE = 3i32;
pub type MF_FILE_FLAGS = i32;
pub const MF_FILEFLAGS_NONE: MF_FILE_FLAGS = 0i32;
pub const MF_FILEFLAGS_NOBUFFERING: MF_FILE_FLAGS = 1i32;
pub const MF_FILEFLAGS_ALLOW_WRITE_SHARING: MF_FILE_FLAGS = 2i32;
pub type MF_FILE_OPENMODE = i32;
pub const MF_OPENMODE_FAIL_IF_NOT_EXIST: MF_FILE_OPENMODE = 0i32;
pub const MF_OPENMODE_FAIL_IF_EXIST: MF_FILE_OPENMODE = 1i32;
pub const MF_OPENMODE_RESET_IF_EXIST: MF_FILE_OPENMODE = 2i32;
pub const MF_OPENMODE_APPEND_IF_EXIST: MF_FILE_OPENMODE = 3i32;
pub const MF_OPENMODE_DELETE_IF_EXIST: MF_FILE_OPENMODE = 4i32;
#[repr(C)]
pub struct MF_FLOAT2 {
    pub x: f32,
    pub y: f32,
}
impl ::core::marker::Copy for MF_FLOAT2 {}
impl ::core::clone::Clone for MF_FLOAT2 {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MF_FLOAT3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}
impl ::core::marker::Copy for MF_FLOAT3 {}
impl ::core::clone::Clone for MF_FLOAT3 {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MF_FRAMESERVER_VCAMEVENT_EXTENDED_CUSTOM_EVENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1851345052,
    data2: 18387,
    data3: 17511,
    data4: [131, 239, 18, 211, 78, 135, 22, 101],
};
pub const MF_FRAMESERVER_VCAMEVENT_EXTENDED_PIPELINE_SHUTDOWN: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1168644913,
    data2: 17400,
    data3: 20061,
    data4: [140, 226, 34, 220, 224, 38, 153, 109],
};
pub const MF_FRAMESERVER_VCAMEVENT_EXTENDED_SOURCE_INITIALIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3844886015,
    data2: 58477,
    data3: 19723,
    data4: [188, 117, 221, 212, 200, 114, 63, 150],
};
pub const MF_FRAMESERVER_VCAMEVENT_EXTENDED_SOURCE_START: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2985212297, data2: 46166, data3: 20298, data4: [174, 64, 7, 156, 40, 226, 74, 248] };
pub const MF_FRAMESERVER_VCAMEVENT_EXTENDED_SOURCE_STOP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3086908001,
    data2: 65169,
    data3: 16734,
    data4: [134, 8, 211, 125, 237, 177, 165, 139],
};
pub const MF_FRAMESERVER_VCAMEVENT_EXTENDED_SOURCE_UNINITIALIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2699799463, data2: 42018, data3: 20019, data4: [132, 1, 179, 125, 40, 0, 170, 103] };
pub const MF_GRL_ABSENT: u32 = 4096u32;
pub const MF_GRL_LOAD_FAILED: u32 = 16u32;
pub type MF_HDCP_STATUS = i32;
pub const MF_HDCP_STATUS_ON: MF_HDCP_STATUS = 0i32;
pub const MF_HDCP_STATUS_OFF: MF_HDCP_STATUS = 1i32;
pub const MF_HDCP_STATUS_ON_WITH_TYPE_ENFORCEMENT: MF_HDCP_STATUS = 2i32;
pub const MF_HISTOGRAM_CHANNEL_B: u32 = 8u32;
pub const MF_HISTOGRAM_CHANNEL_Cb: u32 = 16u32;
pub const MF_HISTOGRAM_CHANNEL_Cr: u32 = 32u32;
pub const MF_HISTOGRAM_CHANNEL_G: u32 = 4u32;
pub const MF_HISTOGRAM_CHANNEL_R: u32 = 2u32;
pub const MF_HISTOGRAM_CHANNEL_Y: u32 = 1u32;
pub const MF_INDEPENDENT_STILL_IMAGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3927093057,
    data2: 1808,
    data3: 17097,
    data4: [161, 39, 218, 163, 231, 132, 131, 165],
};
pub const MF_INDEX_SIZE_ERR: u32 = 2154823681u32;
pub const MF_INVALID_ACCESS_ERR: u32 = 2154823695u32;
pub const MF_INVALID_GRL_SIGNATURE: u32 = 32u32;
pub const MF_INVALID_PRESENTATION_TIME: u64 = 9223372036854775808u64;
pub const MF_INVALID_STATE_ERR: u32 = 2154823691u32;
pub const MF_I_MANUAL_PROXY: ::windows_sys::core::HRESULT = 1074610802i32;
pub const MF_KERNEL_MODE_COMPONENT_LOAD: u32 = 2u32;
#[repr(C)]
pub struct MF_LEAKY_BUCKET_PAIR {
    pub dwBitrate: u32,
    pub msBufferWindow: u32,
}
impl ::core::marker::Copy for MF_LEAKY_BUCKET_PAIR {}
impl ::core::clone::Clone for MF_LEAKY_BUCKET_PAIR {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MF_LOCAL_MFT_REGISTRATION_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3723874204,
    data2: 17670,
    data3: 17834,
    data4: [171, 240, 109, 93, 148, 221, 27, 74],
};
pub const MF_LOCAL_PLUGIN_CONTROL_POLICY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3642425477,
    data2: 51309,
    data3: 20353,
    data4: [136, 34, 140, 104, 225, 215, 250, 4],
};
pub const MF_LOW_LATENCY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2619836698,
    data2: 60794,
    data3: 16609,
    data4: [136, 232, 178, 39, 39, 160, 36, 238],
};
pub const MF_LUMA_KEY_ENABLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1936294415, data2: 30430, data3: 17354, data4: [146, 132, 71, 184, 243, 126, 6, 73] };
pub const MF_LUMA_KEY_LOWER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2480388309, data2: 2945, data3: 18197, data4: [174, 160, 135, 37, 135, 22, 33, 233] };
pub const MF_LUMA_KEY_UPPER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3500095931, data2: 17922, data3: 19505, data4: [167, 6, 161, 33, 113, 165, 17, 10] };
pub type MF_MEDIAKEYSESSION_MESSAGETYPE = i32;
pub const MF_MEDIAKEYSESSION_MESSAGETYPE_LICENSE_REQUEST: MF_MEDIAKEYSESSION_MESSAGETYPE = 0i32;
pub const MF_MEDIAKEYSESSION_MESSAGETYPE_LICENSE_RENEWAL: MF_MEDIAKEYSESSION_MESSAGETYPE = 1i32;
pub const MF_MEDIAKEYSESSION_MESSAGETYPE_LICENSE_RELEASE: MF_MEDIAKEYSESSION_MESSAGETYPE = 2i32;
pub const MF_MEDIAKEYSESSION_MESSAGETYPE_INDIVIDUALIZATION_REQUEST: MF_MEDIAKEYSESSION_MESSAGETYPE = 3i32;
pub type MF_MEDIAKEYSESSION_TYPE = i32;
pub const MF_MEDIAKEYSESSION_TYPE_TEMPORARY: MF_MEDIAKEYSESSION_TYPE = 0i32;
pub const MF_MEDIAKEYSESSION_TYPE_PERSISTENT_LICENSE: MF_MEDIAKEYSESSION_TYPE = 1i32;
pub const MF_MEDIAKEYSESSION_TYPE_PERSISTENT_RELEASE_MESSAGE: MF_MEDIAKEYSESSION_TYPE = 2i32;
pub const MF_MEDIAKEYSESSION_TYPE_PERSISTENT_USAGE_RECORD: MF_MEDIAKEYSESSION_TYPE = 3i32;
pub type MF_MEDIAKEYS_REQUIREMENT = i32;
pub const MF_MEDIAKEYS_REQUIREMENT_REQUIRED: MF_MEDIAKEYS_REQUIREMENT = 1i32;
pub const MF_MEDIAKEYS_REQUIREMENT_OPTIONAL: MF_MEDIAKEYS_REQUIREMENT = 2i32;
pub const MF_MEDIAKEYS_REQUIREMENT_NOT_ALLOWED: MF_MEDIAKEYS_REQUIREMENT = 3i32;
pub type MF_MEDIAKEY_STATUS = i32;
pub const MF_MEDIAKEY_STATUS_USABLE: MF_MEDIAKEY_STATUS = 0i32;
pub const MF_MEDIAKEY_STATUS_EXPIRED: MF_MEDIAKEY_STATUS = 1i32;
pub const MF_MEDIAKEY_STATUS_OUTPUT_DOWNSCALED: MF_MEDIAKEY_STATUS = 2i32;
pub const MF_MEDIAKEY_STATUS_OUTPUT_NOT_ALLOWED: MF_MEDIAKEY_STATUS = 3i32;
pub const MF_MEDIAKEY_STATUS_STATUS_PENDING: MF_MEDIAKEY_STATUS = 4i32;
pub const MF_MEDIAKEY_STATUS_INTERNAL_ERROR: MF_MEDIAKEY_STATUS = 5i32;
pub const MF_MEDIAKEY_STATUS_RELEASED: MF_MEDIAKEY_STATUS = 6i32;
pub const MF_MEDIAKEY_STATUS_OUTPUT_RESTRICTED: MF_MEDIAKEY_STATUS = 7i32;
pub const MF_MEDIASINK_AUTOFINALIZE_SUPPORTED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1220620734, data2: 4954, data3: 16843, data4: [130, 144, 3, 101, 37, 9, 201, 153] };
pub const MF_MEDIASINK_ENABLE_AUTOFINALIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 872497765, data2: 52094, data3: 19678, data4: [172, 124, 239, 253, 59, 60, 37, 48] };
pub const MF_MEDIASOURCE_EXPOSE_ALL_STREAMS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3891417272,
    data2: 36825,
    data3: 18953,
    data4: [182, 193, 106, 49, 92, 124, 114, 14],
};
pub const MF_MEDIASOURCE_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4036596471,
    data2: 40890,
    data3: 19530,
    data4: [163, 127, 140, 71, 180, 225, 223, 231],
};
pub const MF_MEDIATYPE_EQUAL_FORMAT_DATA: u32 = 4u32;
pub const MF_MEDIATYPE_EQUAL_FORMAT_TYPES: u32 = 2u32;
pub const MF_MEDIATYPE_EQUAL_FORMAT_USER_DATA: u32 = 8u32;
pub const MF_MEDIATYPE_EQUAL_MAJOR_TYPES: u32 = 1u32;
pub const MF_MEDIATYPE_MULTIPLEXED_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 331845557, data2: 62069, data3: 20128, data4: [187, 95, 2, 73, 131, 43, 13, 110] };
pub const MF_MEDIA_ENGINE_AUDIO_CATEGORY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3369387293, data2: 13582, data3: 16882, data4: [186, 70, 250, 235, 187, 8, 87, 246] };
pub const MF_MEDIA_ENGINE_AUDIO_ENDPOINT_ROLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3536557009,
    data2: 4458,
    data3: 17650,
    data4: [147, 133, 247, 208, 253, 162, 251, 70],
};
pub const MF_MEDIA_ENGINE_BROWSER_COMPATIBILITY_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1308758754,
    data2: 57743,
    data3: 16865,
    data4: [149, 229, 192, 231, 233, 35, 91, 195],
};
pub const MF_MEDIA_ENGINE_BROWSER_COMPATIBILITY_MODE_IE10: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 295992061, data2: 25993, data3: 16676, data4: [179, 18, 97, 88, 236, 81, 127, 195] };
pub const MF_MEDIA_ENGINE_BROWSER_COMPATIBILITY_MODE_IE11: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 485568863, data2: 52799, data3: 16437, data4: [147, 145, 22, 20, 47, 119, 81, 137] };
pub const MF_MEDIA_ENGINE_BROWSER_COMPATIBILITY_MODE_IE9: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 86781241, data2: 16576, data3: 16776, data4: [171, 134, 248, 40, 39, 59, 117, 34] };
pub const MF_MEDIA_ENGINE_BROWSER_COMPATIBILITY_MODE_IE_EDGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2801001573,
    data2: 15050,
    data3: 17452,
    data4: [163, 240, 173, 109, 218, 216, 57, 174],
};
pub const MF_MEDIA_ENGINE_CALLBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3322118584, data2: 33700, data3: 16888, data4: [163, 208, 222, 5, 7, 104, 73, 169] };
pub type MF_MEDIA_ENGINE_CANPLAY = i32;
pub const MF_MEDIA_ENGINE_CANPLAY_NOT_SUPPORTED: MF_MEDIA_ENGINE_CANPLAY = 0i32;
pub const MF_MEDIA_ENGINE_CANPLAY_MAYBE: MF_MEDIA_ENGINE_CANPLAY = 1i32;
pub const MF_MEDIA_ENGINE_CANPLAY_PROBABLY: MF_MEDIA_ENGINE_CANPLAY = 2i32;
pub const MF_MEDIA_ENGINE_COMPATIBILITY_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1056074452,
    data2: 56404,
    data3: 17886,
    data4: [185, 175, 118, 200, 198, 107, 250, 142],
};
pub const MF_MEDIA_ENGINE_COMPATIBILITY_MODE_WIN10: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1529208969,
    data2: 27815,
    data3: 16697,
    data4: [162, 203, 252, 170, 179, 149, 82, 163],
};
pub const MF_MEDIA_ENGINE_COMPATIBILITY_MODE_WWA_EDGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 364023960,
    data2: 40705,
    data3: 20045,
    data4: [182, 90, 192, 108, 108, 137, 218, 42],
};
pub const MF_MEDIA_ENGINE_CONTENT_PROTECTION_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3761570339,
    data2: 23215,
    data3: 19830,
    data4: [167, 195, 6, 222, 112, 137, 77, 180],
};
pub const MF_MEDIA_ENGINE_CONTENT_PROTECTION_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4258717610,
    data2: 48517,
    data3: 19187,
    data4: [158, 15, 160, 29, 83, 157, 135, 106],
};
pub const MF_MEDIA_ENGINE_CONTINUE_ON_CODEC_ERROR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3687692281, data2: 18660, data3: 17045, data4: [183, 13, 213, 24, 35, 78, 235, 56] };
pub const MF_MEDIA_ENGINE_COREWINDOW: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4241155292,
    data2: 2943,
    data3: 16834,
    data4: [159, 150, 70, 89, 148, 138, 205, 220],
};
pub type MF_MEDIA_ENGINE_CREATEFLAGS = i32;
pub const MF_MEDIA_ENGINE_AUDIOONLY: MF_MEDIA_ENGINE_CREATEFLAGS = 1i32;
pub const MF_MEDIA_ENGINE_WAITFORSTABLE_STATE: MF_MEDIA_ENGINE_CREATEFLAGS = 2i32;
pub const MF_MEDIA_ENGINE_FORCEMUTE: MF_MEDIA_ENGINE_CREATEFLAGS = 4i32;
pub const MF_MEDIA_ENGINE_REAL_TIME_MODE: MF_MEDIA_ENGINE_CREATEFLAGS = 8i32;
pub const MF_MEDIA_ENGINE_DISABLE_LOCAL_PLUGINS: MF_MEDIA_ENGINE_CREATEFLAGS = 16i32;
pub const MF_MEDIA_ENGINE_CREATEFLAGS_MASK: MF_MEDIA_ENGINE_CREATEFLAGS = 31i32;
pub const MF_MEDIA_ENGINE_DXGI_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 106365658, data2: 4244, data3: 18541, data4: [134, 23, 238, 124, 196, 238, 70, 72] };
pub const MF_MEDIA_ENGINE_EME_CALLBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1229280167, data2: 42113, data3: 19639, data4: [190, 197, 56, 9, 3, 81, 55, 49] };
pub type MF_MEDIA_ENGINE_ERR = i32;
pub const MF_MEDIA_ENGINE_ERR_NOERROR: MF_MEDIA_ENGINE_ERR = 0i32;
pub const MF_MEDIA_ENGINE_ERR_ABORTED: MF_MEDIA_ENGINE_ERR = 1i32;
pub const MF_MEDIA_ENGINE_ERR_NETWORK: MF_MEDIA_ENGINE_ERR = 2i32;
pub const MF_MEDIA_ENGINE_ERR_DECODE: MF_MEDIA_ENGINE_ERR = 3i32;
pub const MF_MEDIA_ENGINE_ERR_SRC_NOT_SUPPORTED: MF_MEDIA_ENGINE_ERR = 4i32;
pub const MF_MEDIA_ENGINE_ERR_ENCRYPTED: MF_MEDIA_ENGINE_ERR = 5i32;
pub type MF_MEDIA_ENGINE_EVENT = i32;
pub const MF_MEDIA_ENGINE_EVENT_LOADSTART: MF_MEDIA_ENGINE_EVENT = 1i32;
pub const MF_MEDIA_ENGINE_EVENT_PROGRESS: MF_MEDIA_ENGINE_EVENT = 2i32;
pub const MF_MEDIA_ENGINE_EVENT_SUSPEND: MF_MEDIA_ENGINE_EVENT = 3i32;
pub const MF_MEDIA_ENGINE_EVENT_ABORT: MF_MEDIA_ENGINE_EVENT = 4i32;
pub const MF_MEDIA_ENGINE_EVENT_ERROR: MF_MEDIA_ENGINE_EVENT = 5i32;
pub const MF_MEDIA_ENGINE_EVENT_EMPTIED: MF_MEDIA_ENGINE_EVENT = 6i32;
pub const MF_MEDIA_ENGINE_EVENT_STALLED: MF_MEDIA_ENGINE_EVENT = 7i32;
pub const MF_MEDIA_ENGINE_EVENT_PLAY: MF_MEDIA_ENGINE_EVENT = 8i32;
pub const MF_MEDIA_ENGINE_EVENT_PAUSE: MF_MEDIA_ENGINE_EVENT = 9i32;
pub const MF_MEDIA_ENGINE_EVENT_LOADEDMETADATA: MF_MEDIA_ENGINE_EVENT = 10i32;
pub const MF_MEDIA_ENGINE_EVENT_LOADEDDATA: MF_MEDIA_ENGINE_EVENT = 11i32;
pub const MF_MEDIA_ENGINE_EVENT_WAITING: MF_MEDIA_ENGINE_EVENT = 12i32;
pub const MF_MEDIA_ENGINE_EVENT_PLAYING: MF_MEDIA_ENGINE_EVENT = 13i32;
pub const MF_MEDIA_ENGINE_EVENT_CANPLAY: MF_MEDIA_ENGINE_EVENT = 14i32;
pub const MF_MEDIA_ENGINE_EVENT_CANPLAYTHROUGH: MF_MEDIA_ENGINE_EVENT = 15i32;
pub const MF_MEDIA_ENGINE_EVENT_SEEKING: MF_MEDIA_ENGINE_EVENT = 16i32;
pub const MF_MEDIA_ENGINE_EVENT_SEEKED: MF_MEDIA_ENGINE_EVENT = 17i32;
pub const MF_MEDIA_ENGINE_EVENT_TIMEUPDATE: MF_MEDIA_ENGINE_EVENT = 18i32;
pub const MF_MEDIA_ENGINE_EVENT_ENDED: MF_MEDIA_ENGINE_EVENT = 19i32;
pub const MF_MEDIA_ENGINE_EVENT_RATECHANGE: MF_MEDIA_ENGINE_EVENT = 20i32;
pub const MF_MEDIA_ENGINE_EVENT_DURATIONCHANGE: MF_MEDIA_ENGINE_EVENT = 21i32;
pub const MF_MEDIA_ENGINE_EVENT_VOLUMECHANGE: MF_MEDIA_ENGINE_EVENT = 22i32;
pub const MF_MEDIA_ENGINE_EVENT_FORMATCHANGE: MF_MEDIA_ENGINE_EVENT = 1000i32;
pub const MF_MEDIA_ENGINE_EVENT_PURGEQUEUEDEVENTS: MF_MEDIA_ENGINE_EVENT = 1001i32;
pub const MF_MEDIA_ENGINE_EVENT_TIMELINE_MARKER: MF_MEDIA_ENGINE_EVENT = 1002i32;
pub const MF_MEDIA_ENGINE_EVENT_BALANCECHANGE: MF_MEDIA_ENGINE_EVENT = 1003i32;
pub const MF_MEDIA_ENGINE_EVENT_DOWNLOADCOMPLETE: MF_MEDIA_ENGINE_EVENT = 1004i32;
pub const MF_MEDIA_ENGINE_EVENT_BUFFERINGSTARTED: MF_MEDIA_ENGINE_EVENT = 1005i32;
pub const MF_MEDIA_ENGINE_EVENT_BUFFERINGENDED: MF_MEDIA_ENGINE_EVENT = 1006i32;
pub const MF_MEDIA_ENGINE_EVENT_FRAMESTEPCOMPLETED: MF_MEDIA_ENGINE_EVENT = 1007i32;
pub const MF_MEDIA_ENGINE_EVENT_NOTIFYSTABLESTATE: MF_MEDIA_ENGINE_EVENT = 1008i32;
pub const MF_MEDIA_ENGINE_EVENT_FIRSTFRAMEREADY: MF_MEDIA_ENGINE_EVENT = 1009i32;
pub const MF_MEDIA_ENGINE_EVENT_TRACKSCHANGE: MF_MEDIA_ENGINE_EVENT = 1010i32;
pub const MF_MEDIA_ENGINE_EVENT_OPMINFO: MF_MEDIA_ENGINE_EVENT = 1011i32;
pub const MF_MEDIA_ENGINE_EVENT_RESOURCELOST: MF_MEDIA_ENGINE_EVENT = 1012i32;
pub const MF_MEDIA_ENGINE_EVENT_DELAYLOADEVENT_CHANGED: MF_MEDIA_ENGINE_EVENT = 1013i32;
pub const MF_MEDIA_ENGINE_EVENT_STREAMRENDERINGERROR: MF_MEDIA_ENGINE_EVENT = 1014i32;
pub const MF_MEDIA_ENGINE_EVENT_SUPPORTEDRATES_CHANGED: MF_MEDIA_ENGINE_EVENT = 1015i32;
pub const MF_MEDIA_ENGINE_EVENT_AUDIOENDPOINTCHANGE: MF_MEDIA_ENGINE_EVENT = 1016i32;
pub const MF_MEDIA_ENGINE_EXTENSION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 822738246, data2: 1549, data3: 19298, data4: [141, 207, 250, 255, 129, 19, 24, 210] };
pub type MF_MEDIA_ENGINE_EXTENSION_TYPE = i32;
pub const MF_MEDIA_ENGINE_EXTENSION_TYPE_MEDIASOURCE: MF_MEDIA_ENGINE_EXTENSION_TYPE = 0i32;
pub const MF_MEDIA_ENGINE_EXTENSION_TYPE_BYTESTREAM: MF_MEDIA_ENGINE_EXTENSION_TYPE = 1i32;
pub type MF_MEDIA_ENGINE_FRAME_PROTECTION_FLAGS = i32;
pub const MF_MEDIA_ENGINE_FRAME_PROTECTION_FLAG_PROTECTED: MF_MEDIA_ENGINE_FRAME_PROTECTION_FLAGS = 1i32;
pub const MF_MEDIA_ENGINE_FRAME_PROTECTION_FLAG_REQUIRES_SURFACE_PROTECTION: MF_MEDIA_ENGINE_FRAME_PROTECTION_FLAGS = 2i32;
pub const MF_MEDIA_ENGINE_FRAME_PROTECTION_FLAG_REQUIRES_ANTI_SCREEN_SCRAPE_PROTECTION: MF_MEDIA_ENGINE_FRAME_PROTECTION_FLAGS = 4i32;
pub type MF_MEDIA_ENGINE_KEYERR = i32;
pub const MF_MEDIAENGINE_KEYERR_UNKNOWN: MF_MEDIA_ENGINE_KEYERR = 1i32;
pub const MF_MEDIAENGINE_KEYERR_CLIENT: MF_MEDIA_ENGINE_KEYERR = 2i32;
pub const MF_MEDIAENGINE_KEYERR_SERVICE: MF_MEDIA_ENGINE_KEYERR = 3i32;
pub const MF_MEDIAENGINE_KEYERR_OUTPUT: MF_MEDIA_ENGINE_KEYERR = 4i32;
pub const MF_MEDIAENGINE_KEYERR_HARDWARECHANGE: MF_MEDIA_ENGINE_KEYERR = 5i32;
pub const MF_MEDIAENGINE_KEYERR_DOMAIN: MF_MEDIA_ENGINE_KEYERR = 6i32;
pub const MF_MEDIA_ENGINE_MEDIA_PLAYER_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1037929797,
    data2: 23201,
    data3: 16658,
    data4: [130, 229, 54, 246, 162, 25, 126, 110],
};
pub const MF_MEDIA_ENGINE_NEEDKEY_CALLBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2124941379,
    data2: 46820,
    data3: 17196,
    data4: [142, 164, 120, 72, 255, 228, 34, 14],
};
pub type MF_MEDIA_ENGINE_NETWORK = i32;
pub const MF_MEDIA_ENGINE_NETWORK_EMPTY: MF_MEDIA_ENGINE_NETWORK = 0i32;
pub const MF_MEDIA_ENGINE_NETWORK_IDLE: MF_MEDIA_ENGINE_NETWORK = 1i32;
pub const MF_MEDIA_ENGINE_NETWORK_LOADING: MF_MEDIA_ENGINE_NETWORK = 2i32;
pub const MF_MEDIA_ENGINE_NETWORK_NO_SOURCE: MF_MEDIA_ENGINE_NETWORK = 3i32;
pub const MF_MEDIA_ENGINE_OPM_HWND: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2696842983, data2: 1394, data3: 20268, data4: [168, 1, 42, 21, 27, 211, 231, 38] };
pub type MF_MEDIA_ENGINE_OPM_STATUS = i32;
pub const MF_MEDIA_ENGINE_OPM_NOT_REQUESTED: MF_MEDIA_ENGINE_OPM_STATUS = 0i32;
pub const MF_MEDIA_ENGINE_OPM_ESTABLISHED: MF_MEDIA_ENGINE_OPM_STATUS = 1i32;
pub const MF_MEDIA_ENGINE_OPM_FAILED_VM: MF_MEDIA_ENGINE_OPM_STATUS = 2i32;
pub const MF_MEDIA_ENGINE_OPM_FAILED_BDA: MF_MEDIA_ENGINE_OPM_STATUS = 3i32;
pub const MF_MEDIA_ENGINE_OPM_FAILED_UNSIGNED_DRIVER: MF_MEDIA_ENGINE_OPM_STATUS = 4i32;
pub const MF_MEDIA_ENGINE_OPM_FAILED: MF_MEDIA_ENGINE_OPM_STATUS = 5i32;
pub const MF_MEDIA_ENGINE_PLAYBACK_HWND: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3649603483,
    data2: 26569,
    data3: 19858,
    data4: [186, 167, 110, 173, 212, 70, 3, 157],
};
pub const MF_MEDIA_ENGINE_PLAYBACK_VISUAL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1844171375,
    data2: 27321,
    data3: 19838,
    data4: [176, 238, 198, 26, 115, 255, 173, 21],
};
pub type MF_MEDIA_ENGINE_PRELOAD = i32;
pub const MF_MEDIA_ENGINE_PRELOAD_MISSING: MF_MEDIA_ENGINE_PRELOAD = 0i32;
pub const MF_MEDIA_ENGINE_PRELOAD_EMPTY: MF_MEDIA_ENGINE_PRELOAD = 1i32;
pub const MF_MEDIA_ENGINE_PRELOAD_NONE: MF_MEDIA_ENGINE_PRELOAD = 2i32;
pub const MF_MEDIA_ENGINE_PRELOAD_METADATA: MF_MEDIA_ENGINE_PRELOAD = 3i32;
pub const MF_MEDIA_ENGINE_PRELOAD_AUTOMATIC: MF_MEDIA_ENGINE_PRELOAD = 4i32;
pub type MF_MEDIA_ENGINE_PROTECTION_FLAGS = i32;
pub const MF_MEDIA_ENGINE_ENABLE_PROTECTED_CONTENT: MF_MEDIA_ENGINE_PROTECTION_FLAGS = 1i32;
pub const MF_MEDIA_ENGINE_USE_PMP_FOR_ALL_CONTENT: MF_MEDIA_ENGINE_PROTECTION_FLAGS = 2i32;
pub const MF_MEDIA_ENGINE_USE_UNPROTECTED_PMP: MF_MEDIA_ENGINE_PROTECTION_FLAGS = 4i32;
pub type MF_MEDIA_ENGINE_READY = i32;
pub const MF_MEDIA_ENGINE_READY_HAVE_NOTHING: MF_MEDIA_ENGINE_READY = 0i32;
pub const MF_MEDIA_ENGINE_READY_HAVE_METADATA: MF_MEDIA_ENGINE_READY = 1i32;
pub const MF_MEDIA_ENGINE_READY_HAVE_CURRENT_DATA: MF_MEDIA_ENGINE_READY = 2i32;
pub const MF_MEDIA_ENGINE_READY_HAVE_FUTURE_DATA: MF_MEDIA_ENGINE_READY = 3i32;
pub const MF_MEDIA_ENGINE_READY_HAVE_ENOUGH_DATA: MF_MEDIA_ENGINE_READY = 4i32;
pub type MF_MEDIA_ENGINE_S3D_PACKING_MODE = i32;
pub const MF_MEDIA_ENGINE_S3D_PACKING_MODE_NONE: MF_MEDIA_ENGINE_S3D_PACKING_MODE = 0i32;
pub const MF_MEDIA_ENGINE_S3D_PACKING_MODE_SIDE_BY_SIDE: MF_MEDIA_ENGINE_S3D_PACKING_MODE = 1i32;
pub const MF_MEDIA_ENGINE_S3D_PACKING_MODE_TOP_BOTTOM: MF_MEDIA_ENGINE_S3D_PACKING_MODE = 2i32;
pub type MF_MEDIA_ENGINE_SEEK_MODE = i32;
pub const MF_MEDIA_ENGINE_SEEK_MODE_NORMAL: MF_MEDIA_ENGINE_SEEK_MODE = 0i32;
pub const MF_MEDIA_ENGINE_SEEK_MODE_APPROXIMATE: MF_MEDIA_ENGINE_SEEK_MODE = 1i32;
pub const MF_MEDIA_ENGINE_SOURCE_RESOLVER_CONFIG_STORE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 180405399,
    data2: 46020,
    data3: 18633,
    data4: [156, 222, 187, 140, 162, 68, 44, 163],
};
pub type MF_MEDIA_ENGINE_STATISTIC = i32;
pub const MF_MEDIA_ENGINE_STATISTIC_FRAMES_RENDERED: MF_MEDIA_ENGINE_STATISTIC = 0i32;
pub const MF_MEDIA_ENGINE_STATISTIC_FRAMES_DROPPED: MF_MEDIA_ENGINE_STATISTIC = 1i32;
pub const MF_MEDIA_ENGINE_STATISTIC_BYTES_DOWNLOADED: MF_MEDIA_ENGINE_STATISTIC = 2i32;
pub const MF_MEDIA_ENGINE_STATISTIC_BUFFER_PROGRESS: MF_MEDIA_ENGINE_STATISTIC = 3i32;
pub const MF_MEDIA_ENGINE_STATISTIC_FRAMES_PER_SECOND: MF_MEDIA_ENGINE_STATISTIC = 4i32;
pub const MF_MEDIA_ENGINE_STATISTIC_PLAYBACK_JITTER: MF_MEDIA_ENGINE_STATISTIC = 5i32;
pub const MF_MEDIA_ENGINE_STATISTIC_FRAMES_CORRUPTED: MF_MEDIA_ENGINE_STATISTIC = 6i32;
pub const MF_MEDIA_ENGINE_STATISTIC_TOTAL_FRAME_DELAY: MF_MEDIA_ENGINE_STATISTIC = 7i32;
pub type MF_MEDIA_ENGINE_STREAMTYPE_FAILED = i32;
pub const MF_MEDIA_ENGINE_STREAMTYPE_FAILED_UNKNOWN: MF_MEDIA_ENGINE_STREAMTYPE_FAILED = 0i32;
pub const MF_MEDIA_ENGINE_STREAMTYPE_FAILED_AUDIO: MF_MEDIA_ENGINE_STREAMTYPE_FAILED = 1i32;
pub const MF_MEDIA_ENGINE_STREAMTYPE_FAILED_VIDEO: MF_MEDIA_ENGINE_STREAMTYPE_FAILED = 2i32;
pub const MF_MEDIA_ENGINE_STREAM_CONTAINS_ALPHA_CHANNEL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1556066116,
    data2: 53938,
    data3: 19707,
    data4: [128, 167, 212, 41, 199, 76, 120, 157],
};
pub const MF_MEDIA_ENGINE_SYNCHRONOUS_CLOSE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3284328751,
    data2: 32270,
    data3: 20035,
    data4: [185, 28, 220, 153, 44, 205, 250, 94],
};
pub const MF_MEDIA_ENGINE_TELEMETRY_APPLICATION_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 511387451,
    data2: 42980,
    data3: 16426,
    data4: [143, 81, 196, 142, 136, 162, 202, 188],
};
pub const MF_MEDIA_ENGINE_TIMEDTEXT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2153686033,
    data2: 37600,
    data3: 20057,
    data4: [155, 110, 92, 125, 121, 21, 230, 79],
};
pub const MF_MEDIA_ENGINE_TRACK_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1706992402,
    data2: 16451,
    data3: 18453,
    data4: [142, 171, 68, 220, 226, 239, 143, 42],
};
pub const MF_MEDIA_ENGINE_VIDEO_OUTPUT_FORMAT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1348897084, data2: 36089, data3: 17084, data4: [139, 138, 71, 34, 18, 229, 39, 38] };
pub const MF_MEDIA_PROTECTION_MANAGER_PROPERTIES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 951943593,
    data2: 44266,
    data3: 19571,
    data4: [137, 178, 85, 50, 192, 174, 202, 121],
};
pub const MF_MEDIA_SHARING_ENGINE_DEVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3026306442,
    data2: 31240,
    data3: 19352,
    data4: [153, 168, 112, 253, 95, 59, 173, 253],
};
pub const MF_MEDIA_SHARING_ENGINE_DEVICE_NAME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1998456273,
    data2: 34351,
    data3: 17049,
    data4: [149, 172, 174, 129, 253, 20, 243, 231],
};
pub type MF_MEDIA_SHARING_ENGINE_EVENT = i32;
pub const MF_MEDIA_SHARING_ENGINE_EVENT_DISCONNECT: MF_MEDIA_SHARING_ENGINE_EVENT = 2000i32;
pub const MF_MEDIA_SHARING_ENGINE_INITIAL_SEEK_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1865717749,
    data2: 54568,
    data3: 19023,
    data4: [141, 215, 219, 54, 101, 126, 196, 201],
};
pub const MF_METADATAFACIALEXPRESSION_SMILE: u32 = 1u32;
pub const MF_METADATATIMESTAMPS_DEVICE: u32 = 1u32;
pub const MF_METADATATIMESTAMPS_PRESENTATION: u32 = 2u32;
pub const MF_METADATA_PROVIDER_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3676389508, data2: 22692, data3: 19758, data4: [184, 79, 111, 117, 91, 47, 122, 13] };
pub const MF_MINCRYPT_FAILURE: u32 = 268435456u32;
pub const MF_MP2DLNA_AUDIO_BIT_RATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 756811534,
    data2: 11103,
    data3: 19123,
    data4: [167, 230, 141, 148, 59, 168, 208, 10],
};
pub const MF_MP2DLNA_ENCODE_QUALITY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3039001047, data2: 7494, data3: 20406, data4: [163, 23, 164, 165, 246, 9, 89, 248] };
pub const MF_MP2DLNA_STATISTICS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1977911459,
    data2: 54701,
    data3: 18584,
    data4: [133, 224, 188, 206, 36, 167, 34, 215],
};
pub const MF_MP2DLNA_USE_MMCSS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1425269486,
    data2: 41634,
    data3: 18813,
    data4: [152, 52, 151, 58, 253, 229, 33, 235],
};
pub const MF_MP2DLNA_VIDEO_BIT_RATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3901049054,
    data2: 29620,
    data3: 17111,
    data4: [156, 117, 173, 250, 10, 42, 110, 76],
};
pub const MF_MPEG4SINK_MAX_CODED_SEQUENCES_PER_FRAGMENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4229643222,
    data2: 26925,
    data3: 19685,
    data4: [146, 153, 115, 138, 165, 70, 62, 154],
};
pub const MF_MPEG4SINK_MINIMUM_PROPERTIES_SIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3701599570,
    data2: 17678,
    data3: 18978,
    data4: [140, 98, 78, 212, 82, 247, 161, 135],
};
pub const MF_MPEG4SINK_MIN_FRAGMENT_DURATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2735429388,
    data2: 36605,
    data3: 17896,
    data4: [148, 254, 39, 200, 75, 91, 223, 246],
};
pub const MF_MPEG4SINK_MOOV_BEFORE_MDAT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4134724524, data2: 57830, data3: 20240, data4: [181, 236, 95, 59, 48, 130, 136, 22] };
pub const MF_MPEG4SINK_SPSPPS_PASSTHROUGH: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1442947380,
    data2: 8197,
    data3: 19154,
    data4: [179, 125, 34, 166, 197, 84, 222, 178],
};
pub const MF_MSE_ACTIVELIST_CALLBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2493241871,
    data2: 17737,
    data3: 18133,
    data4: [173, 127, 184, 70, 225, 171, 22, 82],
};
pub type MF_MSE_APPEND_MODE = i32;
pub const MF_MSE_APPEND_MODE_SEGMENTS: MF_MSE_APPEND_MODE = 0i32;
pub const MF_MSE_APPEND_MODE_SEQUENCE: MF_MSE_APPEND_MODE = 1i32;
pub const MF_MSE_BUFFERLIST_CALLBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1122396592,
    data2: 54798,
    data3: 19195,
    data4: [168, 91, 216, 229, 254, 107, 218, 181],
};
pub const MF_MSE_CALLBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2422450112,
    data2: 17093,
    data3: 20477,
    data4: [168, 168, 111, 207, 158, 163, 208, 12],
};
pub type MF_MSE_ERROR = i32;
pub const MF_MSE_ERROR_NOERROR: MF_MSE_ERROR = 0i32;
pub const MF_MSE_ERROR_NETWORK: MF_MSE_ERROR = 1i32;
pub const MF_MSE_ERROR_DECODE: MF_MSE_ERROR = 2i32;
pub const MF_MSE_ERROR_UNKNOWN_ERROR: MF_MSE_ERROR = 3i32;
pub const MF_MSE_OPUS_SUPPORT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1294093505,
    data2: 36036,
    data3: 18595,
    data4: [167, 167, 228, 193, 108, 230, 56, 138],
};
pub type MF_MSE_OPUS_SUPPORT_TYPE = i32;
pub const MF_MSE_OPUS_SUPPORT_ON: MF_MSE_OPUS_SUPPORT_TYPE = 0i32;
pub const MF_MSE_OPUS_SUPPORT_OFF: MF_MSE_OPUS_SUPPORT_TYPE = 1i32;
pub type MF_MSE_READY = i32;
pub const MF_MSE_READY_CLOSED: MF_MSE_READY = 1i32;
pub const MF_MSE_READY_OPEN: MF_MSE_READY = 2i32;
pub const MF_MSE_READY_ENDED: MF_MSE_READY = 3i32;
pub const MF_MSE_VP9_SUPPORT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2463597609,
    data2: 55435,
    data3: 20464,
    data4: [131, 34, 128, 62, 250, 110, 150, 38],
};
pub type MF_MSE_VP9_SUPPORT_TYPE = i32;
pub const MF_MSE_VP9_SUPPORT_DEFAULT: MF_MSE_VP9_SUPPORT_TYPE = 0i32;
pub const MF_MSE_VP9_SUPPORT_ON: MF_MSE_VP9_SUPPORT_TYPE = 1i32;
pub const MF_MSE_VP9_SUPPORT_OFF: MF_MSE_VP9_SUPPORT_TYPE = 2i32;
pub const MF_MT_AAC_AUDIO_PROFILE_LEVEL_INDICATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1983049958,
    data2: 38200,
    data3: 19809,
    data4: [172, 218, 234, 41, 200, 193, 68, 86],
};
pub const MF_MT_AAC_PAYLOAD_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3216686713,
    data2: 29748,
    data3: 19740,
    data4: [148, 240, 114, 163, 185, 225, 113, 136],
};
pub const MF_MT_ALL_SAMPLES_INDEPENDENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3373741881, data2: 24150, data3: 17948, data4: [183, 19, 70, 251, 153, 92, 185, 95] };
pub const MF_MT_ALPHA_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1570085645, data2: 19647, data3: 19716, data4: [145, 159, 63, 95, 127, 40, 66, 17] };
pub const MF_MT_AM_FORMAT_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1943078701, data2: 6256, data3: 16756, data4: [160, 99, 41, 255, 79, 246, 193, 30] };
pub const MF_MT_ARBITRARY_FORMAT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1517662793,
    data2: 3453,
    data3: 18849,
    data4: [161, 195, 224, 216, 127, 12, 173, 229],
};
pub const MF_MT_ARBITRARY_HEADER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2657867509, data2: 265, data3: 20373, data4: [132, 172, 147, 9, 21, 58, 25, 252] };
pub const MF_MT_AUDIO_AVG_BYTES_PER_SECOND: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 447444424, data2: 53231, data3: 17692, data4: [171, 149, 172, 3, 75, 142, 23, 49] };
pub const MF_MT_AUDIO_BITS_PER_SAMPLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4074681727, data2: 16634, data3: 18276, data4: [170, 51, 237, 79, 45, 31, 246, 105] };
pub const MF_MT_AUDIO_BLOCK_ALIGNMENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 841867824, data2: 40683, data3: 17341, data4: [171, 122, 255, 65, 34, 81, 84, 29] };
pub const MF_MT_AUDIO_CHANNEL_MASK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1442535269,
    data2: 25674,
    data3: 19631,
    data4: [132, 121, 147, 137, 131, 187, 21, 136],
};
pub const MF_MT_AUDIO_FLAC_MAX_BLOCK_SIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2340531630, data2: 19290, data3: 19776, data4: [128, 34, 243, 141, 9, 202, 60, 92] };
pub const MF_MT_AUDIO_FLOAT_SAMPLES_PER_SECOND: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4214977098, data2: 53173, data3: 17177, data4: [174, 254, 110, 66, 178, 64, 97, 50] };
pub const MF_MT_AUDIO_FOLDDOWN_MATRIX: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2640482940,
    data2: 14014,
    data3: 19698,
    data4: [181, 196, 163, 146, 110, 62, 135, 17],
};
pub const MF_MT_AUDIO_NUM_CHANNELS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 937724917,
    data2: 25694,
    data3: 19547,
    data4: [137, 222, 173, 169, 226, 155, 105, 106],
};
pub const MF_MT_AUDIO_PREFER_WAVEFORMATEX: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2835458746, data2: 57399, data3: 17802, data4: [189, 246, 84, 91, 226, 7, 64, 66] };
pub const MF_MT_AUDIO_SAMPLES_PER_BLOCK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2863749804, data2: 57658, data3: 18837, data4: [146, 34, 80, 30, 161, 92, 104, 119] };
pub const MF_MT_AUDIO_SAMPLES_PER_SECOND: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1605298919,
    data2: 656,
    data3: 19505,
    data4: [158, 138, 197, 52, 246, 141, 157, 186],
};
pub const MF_MT_AUDIO_VALID_BITS_PER_SAMPLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3653209450,
    data2: 38192,
    data3: 19324,
    data4: [157, 223, 255, 111, 213, 139, 189, 6],
};
pub const MF_MT_AUDIO_WMADRC_AVGREF: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2640482943,
    data2: 14014,
    data3: 19698,
    data4: [181, 196, 163, 146, 110, 62, 135, 17],
};
pub const MF_MT_AUDIO_WMADRC_AVGTARGET: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2640482944,
    data2: 14014,
    data3: 19698,
    data4: [181, 196, 163, 146, 110, 62, 135, 17],
};
pub const MF_MT_AUDIO_WMADRC_PEAKREF: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2640482941,
    data2: 14014,
    data3: 19698,
    data4: [181, 196, 163, 146, 110, 62, 135, 17],
};
pub const MF_MT_AUDIO_WMADRC_PEAKTARGET: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2640482942,
    data2: 14014,
    data3: 19698,
    data4: [181, 196, 163, 146, 110, 62, 135, 17],
};
pub const MF_MT_AVG_BITRATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 540223012, data2: 64269, data3: 19870, data4: [189, 13, 203, 246, 120, 108, 16, 46] };
pub const MF_MT_AVG_BIT_ERROR_RATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2040310742,
    data2: 13576,
    data3: 19892,
    data4: [163, 199, 86, 156, 213, 51, 222, 177],
};
pub const MF_MT_COMPRESSED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 989662446, data2: 6386, data3: 19365, data4: [161, 16, 139, 234, 80, 46, 31, 146] };
pub const MF_MT_CONTAINER_RATE_SCALING: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2206695262,
    data2: 1092,
    data3: 20008,
    data4: [132, 121, 109, 176, 152, 155, 140, 9],
};
pub const MF_MT_CUSTOM_VIDEO_PRIMARIES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1196651027,
    data2: 36091,
    data3: 18210,
    data4: [170, 52, 251, 201, 226, 77, 119, 184],
};
pub const MF_MT_D3D12_CPU_READBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 686727139,
    data2: 54401,
    data3: 18086,
    data4: [185, 138, 127, 105, 213, 40, 14, 130],
};
pub const MF_MT_D3D12_RESOURCE_FLAG_ALLOW_CROSS_ADAPTER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2795627577,
    data2: 12182,
    data3: 19125,
    data4: [152, 220, 173, 247, 73, 115, 80, 93],
};
pub const MF_MT_D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2970848707, data2: 469, data3: 19476, data4: [155, 220, 205, 201, 51, 111, 85, 185] };
pub const MF_MT_D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4004259205,
    data2: 13360,
    data3: 18828,
    data4: [132, 162, 119, 177, 187, 165, 112, 246],
};
pub const MF_MT_D3D12_RESOURCE_FLAG_ALLOW_SIMULTANEOUS_ACCESS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 172572850, data2: 53206, data3: 18232, data4: [157, 2, 152, 17, 55, 52, 1, 90] };
pub const MF_MT_D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2194167367, data2: 20567, data3: 18784, data4: [149, 89, 244, 91, 142, 39, 20, 39] };
pub const MF_MT_D3D12_RESOURCE_FLAG_DENY_SHADER_RESOURCE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3121004460, data2: 65507, data3: 18250, data4: [171, 85, 22, 30, 228, 65, 122, 46] };
pub const MF_MT_D3D12_TEXTURE_LAYOUT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2546490538, data2: 3051, data3: 20193, data4: [151, 21, 242, 47, 173, 140, 16, 245] };
pub const MF_MT_D3D_RESOURCE_VERSION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 391061125, data2: 65062, data3: 17725, data4: [181, 46, 91, 221, 78, 85, 185, 68] };
pub type MF_MT_D3D_RESOURCE_VERSION_ENUM = i32;
pub const MF_D3D11_RESOURCE: MF_MT_D3D_RESOURCE_VERSION_ENUM = 0i32;
pub const MF_D3D12_RESOURCE: MF_MT_D3D_RESOURCE_VERSION_ENUM = 1i32;
pub const MF_MT_DECODER_MAX_DPB_COUNT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1740510284, data2: 34999, data3: 19625, data4: [150, 40, 200, 8, 213, 38, 34, 23] };
pub const MF_MT_DECODER_USE_MAX_RESOLUTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1280605220,
    data2: 44954,
    data3: 20280,
    data4: [150, 173, 151, 135, 115, 207, 83, 231],
};
pub const MF_MT_DEFAULT_STRIDE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1682656840,
    data2: 7682,
    data3: 17686,
    data4: [176, 235, 192, 28, 169, 212, 154, 198],
};
pub const MF_MT_DEPTH_MEASUREMENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4250584201, data2: 2327, data3: 19382, data4: [157, 84, 49, 34, 191, 112, 20, 75] };
pub const MF_MT_DEPTH_VALUE_UNIT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 564658421, data2: 12681, data3: 18327, data4: [190, 186, 241, 60, 217, 163, 26, 94] };
pub const MF_MT_DRM_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2272457507,
    data2: 13658,
    data3: 19655,
    data4: [187, 120, 109, 97, 160, 72, 174, 130],
};
pub const MF_MT_DV_AAUX_CTRL_PACK_0: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4147183694,
    data2: 7633,
    data3: 17685,
    data4: [170, 190, 240, 192, 106, 165, 54, 172],
};
pub const MF_MT_DV_AAUX_CTRL_PACK_1: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3441379085,
    data2: 7940,
    data3: 20448,
    data4: [191, 185, 208, 122, 224, 56, 106, 216],
};
pub const MF_MT_DV_AAUX_SRC_PACK_0: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2227002760,
    data2: 4024,
    data3: 19144,
    data4: [190, 75, 168, 132, 139, 239, 152, 243],
};
pub const MF_MT_DV_AAUX_SRC_PACK_1: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1913546052, data2: 549, data3: 16387, data4: [166, 81, 1, 150, 86, 58, 149, 142] };
pub const MF_MT_DV_VAUX_CTRL_PACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 797237700, data2: 3489, data3: 18312, data4: [147, 142, 13, 251, 251, 179, 75, 72] };
pub const MF_MT_DV_VAUX_SRC_PACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1094725021, data2: 31575, data3: 17350, data4: [177, 41, 44, 185, 151, 241, 80, 9] };
pub const MF_MT_FIXED_SIZE_SAMPLES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3102470063,
    data2: 46872,
    data3: 19972,
    data4: [176, 169, 17, 103, 117, 227, 50, 27],
};
pub const MF_MT_FORWARD_CUSTOM_NALU: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3979570941, data2: 9295, data3: 17037, data4: [145, 83, 40, 243, 153, 69, 136, 144] };
pub const MF_MT_FORWARD_CUSTOM_SEI: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3799212785,
    data2: 45366,
    data3: 16849,
    data4: [149, 148, 58, 126, 79, 235, 242, 209],
};
pub const MF_MT_FRAME_RATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3294208744,
    data2: 15660,
    data3: 20036,
    data4: [177, 50, 254, 229, 21, 108, 123, 176],
};
pub const MF_MT_FRAME_RATE_RANGE_MAX: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3812040001,
    data2: 46287,
    data3: 18949,
    data4: [189, 78, 32, 184, 139, 178, 196, 214],
};
pub const MF_MT_FRAME_RATE_RANGE_MIN: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3538376076,
    data2: 56351,
    data3: 16447,
    data4: [154, 114, 210, 139, 177, 235, 59, 94],
};
pub const MF_MT_FRAME_SIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 374522685, data2: 54962, data3: 16402, data4: [184, 52, 114, 3, 8, 73, 163, 125] };
pub const MF_MT_GEOMETRIC_APERTURE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1718978371,
    data2: 32351,
    data3: 16397,
    data4: [152, 10, 170, 133, 150, 200, 86, 150],
};
pub const MF_MT_H264_CAPABILITIES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3141260552, data2: 18698, data3: 4576, data4: [153, 228, 19, 22, 223, 215, 32, 133] };
pub const MF_MT_H264_LAYOUT_PER_STREAM: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2246220210,
    data2: 37091,
    data3: 20456,
    data4: [178, 245, 192, 103, 224, 191, 229, 122],
};
pub const MF_MT_H264_MAX_CODEC_CONFIG_DELAY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4120025478,
    data2: 19525,
    data3: 20411,
    data4: [187, 73, 108, 197, 52, 208, 91, 155],
};
pub const MF_MT_H264_MAX_MB_PER_SEC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1160080688,
    data2: 29205,
    data3: 17782,
    data4: [147, 54, 176, 241, 188, 213, 155, 178],
};
pub const MF_MT_H264_RATE_CONTROL_MODES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1884387288,
    data2: 17867,
    data3: 4576,
    data4: [172, 125, 185, 28, 224, 215, 32, 133],
};
pub const MF_MT_H264_RESOLUTION_SCALING: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3817161330,
    data2: 63253,
    data3: 18263,
    data4: [186, 144, 27, 105, 108, 119, 52, 87],
};
pub const MF_MT_H264_SIMULCAST_SUPPORT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2661471805,
    data2: 21488,
    data3: 18996,
    data4: [185, 78, 157, 228, 154, 7, 140, 179],
};
pub const MF_MT_H264_SUPPORTED_RATE_CONTROL_MODES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1787479166,
    data2: 20892,
    data3: 20248,
    data4: [155, 179, 126, 234, 174, 165, 89, 77],
};
pub const MF_MT_H264_SUPPORTED_SLICE_MODES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3367901495, data2: 19812, data3: 17737, data4: [131, 67, 168, 8, 108, 11, 253, 165] };
pub const MF_MT_H264_SUPPORTED_SYNC_FRAME_TYPES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2309303297, data2: 62082, data3: 18642, data4: [181, 34, 34, 230, 174, 99, 49, 153] };
pub const MF_MT_H264_SUPPORTED_USAGES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1622256024,
    data2: 56321,
    data3: 16590,
    data4: [151, 54, 171, 168, 69, 162, 219, 220],
};
pub const MF_MT_H264_SVC_CAPABILITIES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4170791614,
    data2: 55607,
    data3: 19087,
    data4: [187, 202, 105, 102, 254, 158, 17, 82],
};
pub const MF_MT_H264_USAGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 899474341, data2: 44800, data3: 18890, data4: [162, 244, 42, 201, 76, 168, 43, 97] };
pub const MF_MT_IMAGE_LOSS_TOLERANT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3976604916, data2: 58190, data3: 18722, data4: [190, 153, 147, 64, 50, 19, 61, 124] };
pub const MF_MT_INTERLACE_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3799141304,
    data2: 58998,
    data3: 18438,
    data4: [180, 178, 168, 214, 239, 180, 76, 205],
};
pub const MF_MT_IN_BAND_PARAMETER_SET: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1977241744,
    data2: 37131,
    data3: 18947,
    data4: [137, 108, 123, 137, 143, 238, 165, 175],
};
pub const MF_MT_MAJOR_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1223401870,
    data2: 63689,
    data3: 18055,
    data4: [191, 17, 10, 116, 201, 249, 106, 143],
};
pub const MF_MT_MAX_FRAME_AVERAGE_LUMINANCE_LEVEL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1490337623,
    data2: 28498,
    data3: 18227,
    data4: [161, 149, 169, 226, 158, 207, 158, 39],
};
pub const MF_MT_MAX_KEYFRAME_SPACING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3245258027, data2: 29601, data3: 18287, data4: [141, 98, 131, 157, 106, 2, 6, 82] };
pub const MF_MT_MAX_LUMINANCE_LEVEL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1344614696,
    data2: 49424,
    data3: 19940,
    data4: [152, 174, 70, 163, 36, 250, 230, 218],
};
pub const MF_MT_MAX_MASTERING_LUMINANCE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3603347863, data2: 10031, data3: 19617, data4: [141, 0, 128, 66, 17, 26, 15, 246] };
pub const MF_MT_MINIMUM_DISPLAY_APERTURE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3610806118,
    data2: 6398,
    data3: 18630,
    data4: [161, 119, 238, 137, 72, 103, 200, 196],
};
pub const MF_MT_MIN_MASTERING_LUMINANCE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2207925344, data2: 20094, data3: 19279, data4: [174, 121, 204, 8, 144, 92, 123, 39] };
pub const MF_MT_MPEG2_CONTENT_PACKET: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2187154916, data2: 20242, data3: 16791, data4: [158, 179, 89, 182, 228, 113, 15, 6] };
pub const MF_MT_MPEG2_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 836999453,
    data2: 63233,
    data3: 19247,
    data4: [180, 38, 138, 227, 189, 169, 224, 75],
};
pub const MF_MT_MPEG2_HDCP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 378477386,
    data2: 16017,
    data3: 17679,
    data4: [174, 167, 228, 186, 234, 218, 229, 186],
};
pub const MF_MT_MPEG2_LEVEL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2532730228,
    data2: 4549,
    data3: 16405,
    data4: [134, 102, 191, 245, 22, 67, 109, 167],
};
pub const MF_MT_MPEG2_ONE_FRAME_PER_PACKET: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2443484853,
    data2: 7456,
    data3: 19266,
    data4: [172, 232, 128, 66, 105, 191, 149, 237],
};
pub const MF_MT_MPEG2_PROFILE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2910234635,
    data2: 11612,
    data3: 19979,
    data4: [179, 117, 100, 229, 32, 19, 112, 54],
};
pub const MF_MT_MPEG2_STANDARD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2718628328,
    data2: 37514,
    data3: 19238,
    data4: [170, 169, 240, 92, 116, 202, 196, 124],
};
pub const MF_MT_MPEG2_TIMECODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1378466320, data2: 58013, data3: 20352, data4: [165, 156, 223, 79, 24, 2, 7, 210] };
pub const MF_MT_MPEG4_CURRENT_SAMPLE_ENTRY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2594693461, data2: 46666, data3: 19485, data4: [165, 0, 69, 93, 96, 11, 101, 96] };
pub const MF_MT_MPEG4_SAMPLE_DESCRIPTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 639540611,
    data2: 38185,
    data3: 19343,
    data4: [161, 17, 139, 156, 149, 10, 129, 169],
};
pub const MF_MT_MPEG4_TRACK_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1425311453,
    data2: 37671,
    data3: 20333,
    data4: [128, 171, 111, 112, 158, 187, 76, 206],
};
pub const MF_MT_MPEG_SEQUENCE_HEADER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1006857703,
    data2: 15056,
    data3: 19614,
    data4: [146, 22, 238, 109, 106, 194, 28, 179],
};
pub const MF_MT_MPEG_START_TIME_CODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2448849029,
    data2: 17203,
    data3: 17024,
    data4: [151, 205, 189, 90, 108, 3, 160, 110],
};
pub const MF_MT_ORIGINAL_4CC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3619569632,
    data2: 11207,
    data3: 18733,
    data4: [184, 67, 97, 161, 145, 155, 112, 195],
};
pub const MF_MT_ORIGINAL_WAVE_FORMAT_TAG: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2361116739, data2: 40921, data3: 18882, data4: [136, 47, 167, 37, 134, 196, 8, 173] };
pub const MF_MT_OUTPUT_BUFFER_NUM: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2768622508,
    data2: 63792,
    data3: 17262,
    data4: [142, 222, 147, 165, 9, 206, 35, 178],
};
pub const MF_MT_PAD_CONTROL_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1292792805,
    data2: 33002,
    data3: 17236,
    data4: [169, 208, 17, 118, 206, 176, 40, 234],
};
pub const MF_MT_PALETTE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1831354178, data2: 38982, data3: 17424, data4: [175, 217, 101, 77, 80, 59, 26, 84] };
pub const MF_MT_PAN_SCAN_APERTURE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2036420062,
    data2: 37255,
    data3: 18683,
    data4: [184, 199, 77, 82, 104, 157, 230, 73],
};
pub const MF_MT_PAN_SCAN_ENABLED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1266641859,
    data2: 35603,
    data3: 16562,
    data4: [169, 147, 171, 246, 48, 184, 32, 78],
};
pub const MF_MT_PIXEL_ASPECT_RATIO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3325520414,
    data2: 36106,
    data3: 16423,
    data4: [190, 69, 109, 154, 10, 211, 155, 182],
};
pub const MF_MT_REALTIME_CONTENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3138572834,
    data2: 11227,
    data3: 16990,
    data4: [145, 236, 35, 8, 225, 137, 165, 143],
};
pub const MF_MT_SAMPLE_SIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3671305080,
    data2: 6544,
    data3: 16523,
    data4: [188, 226, 235, 166, 115, 218, 204, 16],
};
pub const MF_MT_SECURE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3316434173, data2: 772, data3: 20175, data4: [128, 159, 71, 188, 151, 255, 99, 189] };
pub const MF_MT_SOURCE_CONTENT_HINT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1756144588, data2: 8912, data3: 17638, data4: [133, 248, 40, 22, 113, 151, 250, 56] };
pub const MF_MT_SPATIAL_AUDIO_DATA_PRESENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1749219047,
    data2: 54334,
    data3: 20155,
    data4: [156, 156, 201, 111, 65, 120, 72, 99],
};
pub const MF_MT_SPATIAL_AUDIO_MAX_DYNAMIC_OBJECTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3707478602, data2: 9737, data3: 16960, data4: [167, 33, 63, 174, 167, 106, 77, 249] };
pub const MF_MT_SPATIAL_AUDIO_MAX_METADATA_ITEMS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 296386740, data2: 57562, data3: 18374, data4: [128, 96, 150, 193, 37, 154, 229, 13] };
pub const MF_MT_SPATIAL_AUDIO_MIN_METADATA_ITEM_OFFSET_SPACING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2213113545, data2: 4484, data3: 16766, data4: [130, 84, 159, 38, 145, 88, 252, 6] };
pub const MF_MT_SPATIAL_AUDIO_OBJECT_METADATA_FORMAT_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 716643264,
    data2: 25123,
    data3: 19367,
    data4: [173, 100, 123, 148, 180, 122, 231, 146],
};
pub const MF_MT_SPATIAL_AUDIO_OBJECT_METADATA_LENGTH: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 155953342,
    data2: 55075,
    data3: 18591,
    data4: [146, 250, 118, 103, 119, 179, 71, 38],
};
pub const MF_MT_SUBTYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4158868634, data2: 17128, data3: 18196, data4: [183, 75, 203, 41, 215, 44, 53, 229] };
pub const MF_MT_TIMESTAMP_CAN_BE_DTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 613892629, data2: 7035, data3: 16868, data4: [134, 37, 172, 70, 159, 45, 237, 170] };
pub const MF_MT_TRANSFER_FUNCTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1605434601,
    data2: 48732,
    data3: 18741,
    data4: [168, 17, 236, 131, 143, 142, 237, 147],
};
pub const MF_MT_USER_DATA: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3065804383,
    data2: 19515,
    data3: 16548,
    data4: [189, 81, 37, 53, 182, 111, 224, 157],
};
pub const MF_MT_VIDEO_3D: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3411970255,
    data2: 31579,
    data3: 18283,
    data4: [133, 170, 28, 165, 174, 24, 117, 85],
};
pub const MF_MT_VIDEO_3D_FIRST_IS_LEFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3962143891,
    data2: 2778,
    data3: 20129,
    data4: [164, 254, 203, 189, 54, 206, 147, 49],
};
pub const MF_MT_VIDEO_3D_FORMAT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1393940640, data2: 34757, data3: 18071, data4: [183, 147, 102, 6, 198, 124, 4, 155] };
pub const MF_MT_VIDEO_3D_LEFT_IS_BASE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1833663487,
    data2: 22057,
    data3: 17412,
    data4: [148, 140, 198, 52, 244, 206, 38, 212],
};
pub const MF_MT_VIDEO_3D_NUM_VIEWS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3137830538,
    data2: 56511,
    data3: 17131,
    data4: [175, 96, 65, 141, 249, 138, 164, 149],
};
pub const MF_MT_VIDEO_CHROMA_SITING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1709122416, data2: 51059, data3: 19507, data4: [170, 100, 132, 62, 6, 142, 251, 12] };
pub const MF_MT_VIDEO_H264_NO_FMOASO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3980795094,
    data2: 60575,
    data3: 16746,
    data4: [168, 163, 38, 215, 211, 16, 24, 215],
};
pub const MF_MT_VIDEO_LEVEL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2532730228,
    data2: 4549,
    data3: 16405,
    data4: [134, 102, 191, 245, 22, 67, 109, 167],
};
pub const MF_MT_VIDEO_LIGHTING: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1403015836,
    data2: 35083,
    data3: 16918,
    data4: [139, 249, 89, 147, 103, 173, 109, 32],
};
pub const MF_MT_VIDEO_NOMINAL_RANGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3256585957, data2: 47446, data3: 16497, data4: [141, 175, 50, 94, 223, 92, 171, 17] };
pub const MF_MT_VIDEO_NO_FRAME_ORDERING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1062932591, data2: 27586, data3: 20195, data4: [183, 237, 137, 2, 193, 143, 83, 81] };
pub const MF_MT_VIDEO_PRIMARIES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3690718423, data2: 1856, data3: 20192, data4: [129, 146, 133, 10, 176, 226, 25, 53] };
pub const MF_MT_VIDEO_PROFILE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2910234635,
    data2: 11612,
    data3: 19979,
    data4: [179, 117, 100, 229, 32, 19, 112, 54],
};
pub const MF_MT_VIDEO_RENDERER_EXTENSION_PROFILE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2218251449,
    data2: 54344,
    data3: 20429,
    data4: [155, 107, 131, 155, 249, 108, 119, 152],
};
pub const MF_MT_VIDEO_ROTATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3279963741,
    data2: 8817,
    data3: 17036,
    data4: [155, 131, 236, 234, 59, 74, 133, 193],
};
pub const MF_MT_WRAPPED_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1296005923,
    data2: 53295,
    data3: 20076,
    data4: [155, 238, 228, 191, 44, 108, 105, 93],
};
pub const MF_MT_YUV_MATRIX: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1042535504, data2: 11381, data3: 19749, data4: [160, 14, 185, 22, 112, 209, 35, 39] };
pub const MF_NALU_LENGTH_INFORMATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 420630140, data2: 44363, data3: 18015, data4: [187, 24, 32, 24, 98, 135, 182, 175] };
pub const MF_NALU_LENGTH_SET: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2811305299, data2: 4772, data3: 18789, data4: [174, 112, 110, 173, 214, 255, 5, 81] };
pub const MF_NOT_FOUND_ERR: u32 = 2154823688u32;
pub const MF_NOT_SUPPORTED_ERR: u32 = 2154823689u32;
pub type MF_OBJECT_TYPE = i32;
pub const MF_OBJECT_MEDIASOURCE: MF_OBJECT_TYPE = 0i32;
pub const MF_OBJECT_BYTESTREAM: MF_OBJECT_TYPE = 1i32;
pub const MF_OBJECT_INVALID: MF_OBJECT_TYPE = 2i32;
pub type MF_OPM_ACP_PROTECTION_LEVEL = i32;
pub const MF_OPM_ACP_OFF: MF_OPM_ACP_PROTECTION_LEVEL = 0i32;
pub const MF_OPM_ACP_LEVEL_ONE: MF_OPM_ACP_PROTECTION_LEVEL = 1i32;
pub const MF_OPM_ACP_LEVEL_TWO: MF_OPM_ACP_PROTECTION_LEVEL = 2i32;
pub const MF_OPM_ACP_LEVEL_THREE: MF_OPM_ACP_PROTECTION_LEVEL = 3i32;
pub const MF_OPM_ACP_FORCE_ULONG: MF_OPM_ACP_PROTECTION_LEVEL = 2147483647i32;
pub type MF_OPM_CGMSA_PROTECTION_LEVEL = i32;
pub const MF_OPM_CGMSA_OFF: MF_OPM_CGMSA_PROTECTION_LEVEL = 0i32;
pub const MF_OPM_CGMSA_COPY_FREELY: MF_OPM_CGMSA_PROTECTION_LEVEL = 1i32;
pub const MF_OPM_CGMSA_COPY_NO_MORE: MF_OPM_CGMSA_PROTECTION_LEVEL = 2i32;
pub const MF_OPM_CGMSA_COPY_ONE_GENERATION: MF_OPM_CGMSA_PROTECTION_LEVEL = 3i32;
pub const MF_OPM_CGMSA_COPY_NEVER: MF_OPM_CGMSA_PROTECTION_LEVEL = 4i32;
pub const MF_OPM_CGMSA_REDISTRIBUTION_CONTROL_REQUIRED: MF_OPM_CGMSA_PROTECTION_LEVEL = 8i32;
pub const MF_PARSE_ERR: u32 = 2154823761u32;
pub const MF_PD_ADAPTIVE_STREAMING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3926744471, data2: 10745, data3: 18571, data4: [174, 107, 125, 107, 65, 54, 17, 43] };
pub const MF_PD_APP_CONTEXT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969714,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_ASF_CODECLIST: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3837474057,
    data2: 49549,
    data3: 19953,
    data4: [187, 153, 122, 54, 179, 204, 65, 25],
};
pub const MF_PD_ASF_CONTENTENCRYPTIONEX_ENCRYPTION_DATA: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1649445861,
    data2: 60639,
    data3: 18724,
    data4: [163, 89, 114, 186, 179, 57, 123, 157],
};
pub const MF_PD_ASF_CONTENTENCRYPTION_KEYID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2233531966,
    data2: 10110,
    data3: 18154,
    data4: [153, 228, 227, 10, 134, 219, 18, 190],
};
pub const MF_PD_ASF_CONTENTENCRYPTION_LICENSE_URL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2233531968,
    data2: 10110,
    data3: 18154,
    data4: [153, 228, 227, 10, 134, 219, 18, 190],
};
pub const MF_PD_ASF_CONTENTENCRYPTION_SECRET_DATA: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2233531967,
    data2: 10110,
    data3: 18154,
    data4: [153, 228, 227, 10, 134, 219, 18, 190],
};
pub const MF_PD_ASF_CONTENTENCRYPTION_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2233531965,
    data2: 10110,
    data3: 18154,
    data4: [153, 228, 227, 10, 134, 219, 18, 190],
};
pub const MF_PD_ASF_DATA_LENGTH: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3889542120,
    data2: 7977,
    data3: 17875,
    data4: [136, 34, 62, 120, 250, 226, 114, 237],
};
pub const MF_PD_ASF_DATA_START_OFFSET: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3889542119,
    data2: 7977,
    data3: 17875,
    data4: [136, 34, 62, 120, 250, 226, 114, 237],
};
pub const MF_PD_ASF_FILEPROPERTIES_CREATION_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502326,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_FILEPROPERTIES_FILE_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502324,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_FILEPROPERTIES_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502331,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_FILEPROPERTIES_MAX_BITRATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502334,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_FILEPROPERTIES_MAX_PACKET_SIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502333,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_FILEPROPERTIES_MIN_PACKET_SIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502332,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_FILEPROPERTIES_PACKETS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502327,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_FILEPROPERTIES_PLAY_DURATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502328,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_FILEPROPERTIES_PREROLL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502330,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_FILEPROPERTIES_SEND_DURATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1038502329,
    data2: 55149,
    data3: 20070,
    data4: [158, 201, 120, 18, 15, 180, 199, 227],
};
pub const MF_PD_ASF_INFO_HAS_AUDIO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2162565781, data2: 8854, data3: 19012, data4: [179, 28, 209, 3, 198, 254, 210, 60] };
pub const MF_PD_ASF_INFO_HAS_NON_AUDIO_VIDEO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2162565783, data2: 8854, data3: 19012, data4: [179, 28, 209, 3, 198, 254, 210, 60] };
pub const MF_PD_ASF_INFO_HAS_VIDEO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2162565782, data2: 8854, data3: 19012, data4: [179, 28, 209, 3, 198, 254, 210, 60] };
pub const MF_PD_ASF_LANGLIST: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4064142396,
    data2: 39287,
    data3: 17933,
    data4: [166, 236, 50, 147, 127, 22, 15, 125],
};
pub const MF_PD_ASF_LANGLIST_LEGACYORDER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4064142397,
    data2: 39287,
    data3: 17933,
    data4: [166, 236, 50, 147, 127, 22, 15, 125],
};
pub const MF_PD_ASF_MARKER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1362375438,
    data2: 33702,
    data3: 18270,
    data4: [169, 213, 79, 184, 117, 251, 46, 49],
};
pub const MF_PD_ASF_METADATA_IS_VBR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1606849658,
    data2: 61280,
    data3: 17501,
    data4: [180, 73, 68, 46, 204, 120, 180, 193],
};
pub const MF_PD_ASF_METADATA_LEAKY_BUCKET_PAIRS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1606849661,
    data2: 61280,
    data3: 17501,
    data4: [180, 73, 68, 46, 204, 120, 180, 193],
};
pub const MF_PD_ASF_METADATA_V8_BUFFERAVERAGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1606849660,
    data2: 61280,
    data3: 17501,
    data4: [180, 73, 68, 46, 204, 120, 180, 193],
};
pub const MF_PD_ASF_METADATA_V8_VBRPEAK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1606849659,
    data2: 61280,
    data3: 17501,
    data4: [180, 73, 68, 46, 204, 120, 180, 193],
};
pub const MF_PD_ASF_SCRIPT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3801927895,
    data2: 54786,
    data3: 18723,
    data4: [167, 254, 115, 253, 151, 236, 198, 80],
};
pub const MF_PD_AUDIO_ENCODING_BITRATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969717,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_AUDIO_ISVARIABLEBITRATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 855797472, data2: 58247, data3: 17794, data4: [174, 10, 52, 162, 173, 59, 170, 24] };
pub const MF_PD_DURATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969715,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_LAST_MODIFIED_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969720,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_MIME_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969719,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_PLAYBACK_BOUNDARY_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969723,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_PLAYBACK_ELEMENT_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969721,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_PMPHOST_CONTEXT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969713,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_PREFERRED_LANGUAGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969722,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_SAMI_STYLELIST: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3770104959,
    data2: 18541,
    data3: 18510,
    data4: [152, 114, 77, 229, 25, 42, 123, 248],
};
pub const MF_PD_TOTAL_FILE_SIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969716,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub const MF_PD_VIDEO_ENCODING_BITRATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1821969718,
    data2: 48014,
    data3: 18298,
    data4: [133, 152, 13, 93, 150, 252, 216, 138],
};
pub type MF_PLUGIN_CONTROL_POLICY = i32;
pub const MF_PLUGIN_CONTROL_POLICY_USE_ALL_PLUGINS: MF_PLUGIN_CONTROL_POLICY = 0i32;
pub const MF_PLUGIN_CONTROL_POLICY_USE_APPROVED_PLUGINS: MF_PLUGIN_CONTROL_POLICY = 1i32;
pub const MF_PLUGIN_CONTROL_POLICY_USE_WEB_PLUGINS: MF_PLUGIN_CONTROL_POLICY = 2i32;
pub const MF_PLUGIN_CONTROL_POLICY_USE_WEB_PLUGINS_EDGEMODE: MF_PLUGIN_CONTROL_POLICY = 3i32;
pub const MF_PMP_SERVER_CONTEXT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 788580624,
    data2: 53967,
    data3: 17016,
    data4: [139, 106, 208, 119, 250, 195, 162, 95],
};
pub const MF_POLICY_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2975908429,
    data2: 49241,
    data3: 18673,
    data4: [169, 1, 158, 226, 152, 169, 168, 195],
};
pub const MF_PREFERRED_SOURCE_URI: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1606964360, data2: 17258, data3: 19896, data4: [144, 175, 77, 180, 2, 174, 92, 87] };
pub const MF_PROGRESSIVE_CODING_CONTENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2399276778,
    data2: 5384,
    data3: 18207,
    data4: [157, 166, 80, 125, 124, 250, 64, 219],
};
pub const MF_PROPERTY_HANDLER_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2751122946,
    data2: 12984,
    data3: 16861,
    data4: [144, 231, 95, 239, 124, 137, 145, 181],
};
pub type MF_Plugin_Type = i32;
pub const MF_Plugin_Type_MFT: MF_Plugin_Type = 0i32;
pub const MF_Plugin_Type_MediaSource: MF_Plugin_Type = 1i32;
pub const MF_Plugin_Type_MFT_MatchOutputType: MF_Plugin_Type = 2i32;
pub const MF_Plugin_Type_Other: MF_Plugin_Type = -1i32;
pub type MF_QUALITY_ADVISE_FLAGS = i32;
pub const MF_QUALITY_CANNOT_KEEP_UP: MF_QUALITY_ADVISE_FLAGS = 1i32;
pub type MF_QUALITY_DROP_MODE = i32;
pub const MF_DROP_MODE_NONE: MF_QUALITY_DROP_MODE = 0i32;
pub const MF_DROP_MODE_1: MF_QUALITY_DROP_MODE = 1i32;
pub const MF_DROP_MODE_2: MF_QUALITY_DROP_MODE = 2i32;
pub const MF_DROP_MODE_3: MF_QUALITY_DROP_MODE = 3i32;
pub const MF_DROP_MODE_4: MF_QUALITY_DROP_MODE = 4i32;
pub const MF_DROP_MODE_5: MF_QUALITY_DROP_MODE = 5i32;
pub const MF_NUM_DROP_MODES: MF_QUALITY_DROP_MODE = 6i32;
pub type MF_QUALITY_LEVEL = i32;
pub const MF_QUALITY_NORMAL: MF_QUALITY_LEVEL = 0i32;
pub const MF_QUALITY_NORMAL_MINUS_1: MF_QUALITY_LEVEL = 1i32;
pub const MF_QUALITY_NORMAL_MINUS_2: MF_QUALITY_LEVEL = 2i32;
pub const MF_QUALITY_NORMAL_MINUS_3: MF_QUALITY_LEVEL = 3i32;
pub const MF_QUALITY_NORMAL_MINUS_4: MF_QUALITY_LEVEL = 4i32;
pub const MF_QUALITY_NORMAL_MINUS_5: MF_QUALITY_LEVEL = 5i32;
pub const MF_NUM_QUALITY_LEVELS: MF_QUALITY_LEVEL = 6i32;
pub const MF_QUALITY_NOTIFY_PROCESSING_LATENCY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4139010808, data2: 24653, data3: 18174, data4: [169, 93, 69, 71, 155, 16, 201, 188] };
pub const MF_QUALITY_NOTIFY_SAMPLE_LAG: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 819024390, data2: 60714, data3: 18272, data4: [190, 23, 235, 74, 159, 18, 41, 92] };
pub const MF_QUALITY_SERVICES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3085090321,
    data2: 12182,
    data3: 17984,
    data4: [181, 44, 40, 35, 101, 189, 241, 108],
};
#[repr(C)]
pub struct MF_QUATERNION {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub w: f32,
}
impl ::core::marker::Copy for MF_QUATERNION {}
impl ::core::clone::Clone for MF_QUATERNION {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MF_QUOTA_EXCEEDED_ERR: u32 = 2154823702u32;
pub const MF_RATE_CONTROL_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2255463063,
    data2: 47106,
    data3: 19448,
    data4: [157, 201, 94, 59, 106, 159, 83, 201],
};
pub const MF_READWRITE_D3D_OPTIONAL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 560232921, data2: 12401, data3: 17098, data4: [187, 108, 76, 34, 16, 46, 29, 24] };
pub const MF_READWRITE_DISABLE_CONVERTERS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2564141157, data2: 4980, data3: 18503, data4: [141, 93, 49, 82, 15, 238, 113, 86] };
pub const MF_READWRITE_ENABLE_AUTOFINALIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3715932457,
    data2: 36049,
    data3: 19909,
    data4: [157, 222, 206, 22, 134, 117, 222, 97],
};
pub const MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2788469020,
    data2: 33323,
    data3: 16825,
    data4: [164, 148, 77, 228, 100, 54, 18, 176],
};
pub const MF_READWRITE_MMCSS_CLASS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 959988480, data2: 53483, data3: 16561, data4: [135, 160, 51, 24, 135, 27, 90, 83] };
pub const MF_READWRITE_MMCSS_CLASS_AUDIO: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1124616154, data2: 2192, data3: 19214, data4: [147, 140, 5, 67, 50, 197, 71, 225] };
pub const MF_READWRITE_MMCSS_PRIORITY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1135417806,
    data2: 62271,
    data3: 19369,
    data4: [165, 128, 228, 205, 18, 242, 209, 68],
};
pub const MF_READWRITE_MMCSS_PRIORITY_AUDIO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 658356357,
    data2: 11746,
    data3: 19890,
    data4: [166, 167, 253, 182, 111, 180, 11, 97],
};
pub const MF_REMOTE_PROXY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 788580622,
    data2: 53967,
    data3: 17016,
    data4: [139, 106, 208, 119, 250, 195, 162, 95],
};
pub type MF_RESOLUTION_FLAGS = u32;
pub const MF_RESOLUTION_MEDIASOURCE: MF_RESOLUTION_FLAGS = 1u32;
pub const MF_RESOLUTION_BYTESTREAM: MF_RESOLUTION_FLAGS = 2u32;
pub const MF_RESOLUTION_CONTENT_DOES_NOT_HAVE_TO_MATCH_EXTENSION_OR_MIME_TYPE: MF_RESOLUTION_FLAGS = 16u32;
pub const MF_RESOLUTION_KEEP_BYTE_STREAM_ALIVE_ON_FAIL: MF_RESOLUTION_FLAGS = 32u32;
pub const MF_RESOLUTION_DISABLE_LOCAL_PLUGINS: MF_RESOLUTION_FLAGS = 64u32;
pub const MF_RESOLUTION_PLUGIN_CONTROL_POLICY_APPROVED_ONLY: MF_RESOLUTION_FLAGS = 128u32;
pub const MF_RESOLUTION_PLUGIN_CONTROL_POLICY_WEB_ONLY: MF_RESOLUTION_FLAGS = 256u32;
pub const MF_RESOLUTION_PLUGIN_CONTROL_POLICY_WEB_ONLY_EDGEMODE: MF_RESOLUTION_FLAGS = 512u32;
pub const MF_RESOLUTION_ENABLE_STORE_PLUGINS: MF_RESOLUTION_FLAGS = 1024u32;
pub const MF_RESOLUTION_READ: MF_RESOLUTION_FLAGS = 65536u32;
pub const MF_RESOLUTION_WRITE: MF_RESOLUTION_FLAGS = 131072u32;
pub const MF_SAMI_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1235786471, data2: 46297, data3: 20210, data4: [170, 92, 246, 90, 62, 5, 174, 78] };
pub const MF_SAMPLEGRABBERSINK_IGNORE_CLOCK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 251503296,
    data2: 11113,
    data3: 20014,
    data4: [171, 141, 70, 220, 191, 247, 210, 93],
};
pub const MF_SAMPLEGRABBERSINK_SAMPLE_TIME_OFFSET: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1659098998,
    data2: 33024,
    data3: 19971,
    data4: [166, 232, 189, 56, 87, 172, 156, 71],
};
pub const MF_SA_AUDIO_ENDPOINT_AWARE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3224901377,
    data2: 32860,
    data3: 17074,
    data4: [172, 141, 226, 180, 191, 33, 244, 248],
};
pub const MF_SA_BUFFERS_PER_SAMPLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2268877169, data2: 7741, data3: 20005, data4: [152, 141, 180, 51, 206, 4, 25, 131] };
pub const MF_SA_D3D11_ALLOCATE_DISPLAYABLE_RESOURCES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4009414253,
    data2: 11945,
    data3: 19167,
    data4: [187, 223, 123, 188, 72, 42, 27, 109],
};
pub const MF_SA_D3D11_ALLOW_DYNAMIC_YUV_TEXTURE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3456554143,
    data2: 1555,
    data3: 19357,
    data4: [134, 166, 216, 196, 249, 193, 0, 117],
};
pub const MF_SA_D3D11_AWARE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 543903688,
    data2: 64761,
    data3: 19537,
    data4: [175, 227, 151, 100, 54, 158, 51, 160],
};
pub const MF_SA_D3D11_BINDFLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3939473325,
    data2: 1628,
    data3: 17416,
    data4: [190, 227, 253, 203, 253, 18, 139, 226],
};
pub const MF_SA_D3D11_HW_PROTECTED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 982231513,
    data2: 37578,
    data3: 17159,
    data4: [163, 145, 105, 153, 219, 243, 182, 206],
};
pub const MF_SA_D3D11_SHARED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2072982211, data2: 28054, data3: 19337, data4: [146, 3, 221, 56, 182, 20, 20, 243] };
pub const MF_SA_D3D11_SHARED_WITHOUT_MUTEX: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 970708045, data2: 11844, data3: 18737, data4: [164, 200, 53, 45, 61, 196, 33, 21] };
pub const MF_SA_D3D11_USAGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3898598466,
    data2: 11427,
    data3: 18542,
    data4: [169, 199, 16, 157, 218, 96, 152, 128],
};
pub const MF_SA_D3D12_CLEAR_VALUE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2260376121,
    data2: 1318,
    data3: 18781,
    data4: [154, 181, 84, 236, 159, 173, 111, 195],
};
pub const MF_SA_D3D12_HEAP_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1231762022, data2: 53903, data3: 20364, data4: [147, 167, 74, 89, 107, 26, 49, 161] };
pub const MF_SA_D3D12_HEAP_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1458727542,
    data2: 48065,
    data3: 19680,
    data4: [187, 17, 226, 35, 104, 216, 116, 237],
};
pub const MF_SA_D3D_AWARE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3936574505, data2: 30558, data3: 18574, data4: [155, 97, 179, 40, 62, 73, 88, 59] };
pub const MF_SA_MINIMUM_OUTPUT_SAMPLE_COUNT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2232894933, data2: 50134, data3: 18285, data4: [149, 39, 73, 142, 242, 209, 13, 24] };
pub const MF_SA_MINIMUM_OUTPUT_SAMPLE_COUNT_PROGRESSIVE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 257237925, data2: 7346, data3: 18373, data4: [165, 80, 46, 235, 132, 180, 209, 74] };
pub const MF_SA_REQUIRED_SAMPLE_COUNT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 411053153,
    data2: 12875,
    data3: 18770,
    data4: [171, 208, 23, 111, 245, 198, 150, 255],
};
pub const MF_SA_REQUIRED_SAMPLE_COUNT_PROGRESSIVE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2977093006,
    data2: 64119,
    data3: 20040,
    data4: [141, 42, 29, 242, 216, 80, 234, 194],
};
pub const MF_SDK_VERSION: u32 = 2u32;
pub const MF_SD_AMBISONICS_SAMPLE3D_DESCRIPTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4145401662,
    data2: 43364,
    data3: 19519,
    data4: [148, 174, 157, 107, 167, 38, 70, 65],
};
pub const MF_SD_ASF_EXTSTRMPROP_AVG_BUFFERSIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1224254756, data2: 12381, data3: 16941, data4: [133, 36, 37, 2, 221, 163, 54, 128] };
pub const MF_SD_ASF_EXTSTRMPROP_AVG_DATA_BITRATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1224254755, data2: 12381, data3: 16941, data4: [133, 36, 37, 2, 221, 163, 54, 128] };
pub const MF_SD_ASF_EXTSTRMPROP_LANGUAGE_ID_INDEX: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1224254754, data2: 12381, data3: 16941, data4: [133, 36, 37, 2, 221, 163, 54, 128] };
pub const MF_SD_ASF_EXTSTRMPROP_MAX_BUFFERSIZE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1224254758, data2: 12381, data3: 16941, data4: [133, 36, 37, 2, 221, 163, 54, 128] };
pub const MF_SD_ASF_EXTSTRMPROP_MAX_DATA_BITRATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1224254757, data2: 12381, data3: 16941, data4: [133, 36, 37, 2, 221, 163, 54, 128] };
pub const MF_SD_ASF_METADATA_DEVICE_CONFORMANCE_TEMPLATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 610177693,
    data2: 50254,
    data3: 20350,
    data4: [187, 60, 119, 212, 223, 210, 127, 138],
};
pub const MF_SD_ASF_STREAMBITRATES_BITRATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2833351405,
    data2: 45000,
    data3: 17360,
    data4: [176, 209, 246, 91, 173, 157, 165, 88],
};
pub const MF_SD_AUDIO_ENCODER_DELAY: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2391097900, data2: 29662, data3: 16447, data4: [154, 53, 85, 10, 214, 232, 185, 81] };
pub const MF_SD_AUDIO_ENCODER_PADDING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1385987884, data2: 44107, data3: 20031, data4: [191, 195, 9, 2, 25, 73, 130, 203] };
pub const MF_SD_LANGUAGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 11477376, data2: 48578, data3: 16956, data4: [171, 202, 245, 3, 89, 59, 193, 33] };
pub const MF_SD_MEDIASOURCE_STATUS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 420702091, data2: 64527, data3: 17626, data4: [143, 67, 27, 163, 181, 38, 244, 174] };
pub const MF_SD_MUTUALLY_EXCLUSIVE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 37681052,
    data2: 14477,
    data3: 18559,
    data4: [172, 23, 105, 108, 214, 227, 198, 245],
};
pub const MF_SD_PROTECTED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 11477377, data2: 48578, data3: 16956, data4: [171, 202, 245, 3, 89, 59, 193, 33] };
pub const MF_SD_SAMI_LANGUAGE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 922532234,
    data2: 27856,
    data3: 17611,
    data4: [172, 185, 168, 245, 96, 13, 208, 187],
};
pub const MF_SD_STREAM_NAME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1327171997,
    data2: 54036,
    data3: 16869,
    data4: [167, 129, 127, 239, 170, 76, 80, 31],
};
pub const MF_SD_VIDEO_SPHERICAL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2770183241, data2: 16348, data3: 18316, data4: [188, 181, 48, 190, 118, 89, 95, 85] };
pub const MF_SD_VIDEO_SPHERICAL_FORMAT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1250935815,
    data2: 28321,
    data3: 18120,
    data4: [181, 103, 105, 113, 212, 161, 57, 195],
};
pub const MF_SD_VIDEO_SPHERICAL_INITIAL_VIEWDIRECTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 298998345,
    data2: 47970,
    data3: 18047,
    data4: [157, 177, 193, 113, 101, 113, 108, 73],
};
pub type MF_SERVICE_LOOKUP_TYPE = i32;
pub const MF_SERVICE_LOOKUP_UPSTREAM: MF_SERVICE_LOOKUP_TYPE = 0i32;
pub const MF_SERVICE_LOOKUP_UPSTREAM_DIRECT: MF_SERVICE_LOOKUP_TYPE = 1i32;
pub const MF_SERVICE_LOOKUP_DOWNSTREAM: MF_SERVICE_LOOKUP_TYPE = 2i32;
pub const MF_SERVICE_LOOKUP_DOWNSTREAM_DIRECT: MF_SERVICE_LOOKUP_TYPE = 3i32;
pub const MF_SERVICE_LOOKUP_ALL: MF_SERVICE_LOOKUP_TYPE = 4i32;
pub const MF_SERVICE_LOOKUP_GLOBAL: MF_SERVICE_LOOKUP_TYPE = 5i32;
pub const MF_SESSION_APPROX_EVENT_OCCURRENCE_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 420381999,
    data2: 25144,
    data3: 17105,
    data4: [181, 175, 105, 234, 51, 142, 248, 80],
};
pub const MF_SESSION_CONTENT_PROTECTION_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 511956098, data2: 7964, data3: 17777, data4: [132, 5, 136, 244, 178, 24, 31, 116] };
pub const MF_SESSION_GLOBAL_TIME: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 511956098, data2: 7964, data3: 17777, data4: [132, 5, 136, 244, 178, 24, 31, 114] };
pub const MF_SESSION_QUALITY_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 511956098, data2: 7964, data3: 17777, data4: [132, 5, 136, 244, 178, 24, 31, 115] };
pub const MF_SESSION_REMOTE_SOURCE_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4093853428,
    data2: 39859,
    data3: 17272,
    data4: [148, 31, 133, 160, 133, 107, 194, 68],
};
pub const MF_SESSION_SERVER_CONTEXT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2951066257,
    data2: 20730,
    data3: 18152,
    data4: [185, 190, 12, 12, 60, 228, 179, 165],
};
pub const MF_SESSION_TOPOLOADER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 511956098, data2: 7964, data3: 17777, data4: [132, 5, 136, 244, 178, 24, 31, 113] };
pub const MF_SHARING_ENGINE_CALLBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1474043541,
    data2: 53842,
    data3: 17402,
    data4: [155, 188, 24, 0, 112, 238, 254, 109],
};
pub type MF_SHARING_ENGINE_EVENT = i32;
pub const MF_SHARING_ENGINE_EVENT_DISCONNECT: MF_SHARING_ENGINE_EVENT = 2000i32;
pub const MF_SHARING_ENGINE_EVENT_LOCALRENDERINGSTARTED: MF_SHARING_ENGINE_EVENT = 2001i32;
pub const MF_SHARING_ENGINE_EVENT_LOCALRENDERINGENDED: MF_SHARING_ENGINE_EVENT = 2002i32;
pub const MF_SHARING_ENGINE_EVENT_STOPPED: MF_SHARING_ENGINE_EVENT = 2003i32;
pub const MF_SHARING_ENGINE_EVENT_ERROR: MF_SHARING_ENGINE_EVENT = 2501i32;
pub const MF_SHARING_ENGINE_SHAREDRENDERER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4020520608,
    data2: 29671,
    data3: 16462,
    data4: [138, 226, 254, 246, 10, 245, 163, 43],
};
pub const MF_SHUTDOWN_RENDERER_ON_ENGINE_SHUTDOWN: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3239237965,
    data2: 27548,
    data3: 18680,
    data4: [182, 249, 121, 80, 255, 154, 183, 30],
};
pub const MF_SINK_VIDEO_DISPLAY_ASPECT_RATIO_DENOMINATOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1856105367, data2: 8160, data3: 20240, data4: [166, 228, 31, 79, 102, 21, 100, 224] };
pub const MF_SINK_VIDEO_DISPLAY_ASPECT_RATIO_NUMERATOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3505601314,
    data2: 46986,
    data3: 18553,
    data4: [180, 85, 240, 62, 243, 250, 130, 205],
};
pub const MF_SINK_VIDEO_NATIVE_HEIGHT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4039796485,
    data2: 18700,
    data3: 17384,
    data4: [148, 28, 192, 179, 32, 107, 154, 101],
};
pub const MF_SINK_VIDEO_NATIVE_WIDTH: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3872827143, data2: 5381, data3: 18247, data4: [155, 16, 114, 210, 209, 88, 203, 58] };
pub const MF_SINK_VIDEO_PTS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 560119271, data2: 16926, data3: 19344, data4: [155, 51, 229, 143, 191, 29, 88, 182] };
pub const MF_SINK_WRITER_ASYNC_CALLBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1221269566, data2: 31499, data3: 18164, data4: [130, 46, 94, 29, 45, 218, 67, 84] };
pub type MF_SINK_WRITER_CONSTANTS = u32;
pub const MF_SINK_WRITER_INVALID_STREAM_INDEX: MF_SINK_WRITER_CONSTANTS = 4294967295u32;
pub const MF_SINK_WRITER_ALL_STREAMS: MF_SINK_WRITER_CONSTANTS = 4294967294u32;
pub const MF_SINK_WRITER_MEDIASINK: MF_SINK_WRITER_CONSTANTS = 4294967295u32;
pub const MF_SINK_WRITER_D3D_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3967954338,
    data2: 57833,
    data3: 19241,
    data4: [160, 216, 86, 60, 113, 159, 82, 105],
};
pub const MF_SINK_WRITER_DISABLE_THROTTLING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 146294232, data2: 11124, data3: 19198, data4: [157, 83, 190, 22, 210, 213, 174, 79] };
pub const MF_SINK_WRITER_ENCODER_CONFIG: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2912013572,
    data2: 42956,
    data3: 19143,
    data4: [153, 182, 165, 123, 154, 74, 124, 112],
};
#[repr(C)]
pub struct MF_SINK_WRITER_STATISTICS {
    pub cb: u32,
    pub llLastTimestampReceived: i64,
    pub llLastTimestampEncoded: i64,
    pub llLastTimestampProcessed: i64,
    pub llLastStreamTickReceived: i64,
    pub llLastSinkSampleRequest: i64,
    pub qwNumSamplesReceived: u64,
    pub qwNumSamplesEncoded: u64,
    pub qwNumSamplesProcessed: u64,
    pub qwNumStreamTicksReceived: u64,
    pub dwByteCountQueued: u32,
    pub qwByteCountProcessed: u64,
    pub dwNumOutstandingSinkSampleRequests: u32,
    pub dwAverageSampleRateReceived: u32,
    pub dwAverageSampleRateEncoded: u32,
    pub dwAverageSampleRateProcessed: u32,
}
impl ::core::marker::Copy for MF_SINK_WRITER_STATISTICS {}
impl ::core::clone::Clone for MF_SINK_WRITER_STATISTICS {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MF_SOURCE_PRESENTATION_PROVIDER_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3758271196, data2: 62639, data3: 20197, data4: [152, 71, 5, 62, 223, 132, 4, 38] };
pub const MF_SOURCE_READER_ASYNC_CALLBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 507362988, data2: 47939, data3: 19509, data4: [181, 7, 205, 100, 68, 100, 201, 101] };
pub type MF_SOURCE_READER_CONSTANTS = i32;
pub const MF_SOURCE_READER_INVALID_STREAM_INDEX: MF_SOURCE_READER_CONSTANTS = -1i32;
pub const MF_SOURCE_READER_ALL_STREAMS: MF_SOURCE_READER_CONSTANTS = -2i32;
pub const MF_SOURCE_READER_ANY_STREAM: MF_SOURCE_READER_CONSTANTS = -2i32;
pub const MF_SOURCE_READER_FIRST_AUDIO_STREAM: MF_SOURCE_READER_CONSTANTS = -3i32;
pub const MF_SOURCE_READER_FIRST_VIDEO_STREAM: MF_SOURCE_READER_CONSTANTS = -4i32;
pub const MF_SOURCE_READER_MEDIASOURCE: MF_SOURCE_READER_CONSTANTS = -1i32;
pub type MF_SOURCE_READER_CONTROL_FLAG = i32;
pub const MF_SOURCE_READER_CONTROLF_DRAIN: MF_SOURCE_READER_CONTROL_FLAG = 1i32;
pub type MF_SOURCE_READER_CURRENT_TYPE_CONSTANTS = i32;
pub const MF_SOURCE_READER_CURRENT_TYPE_INDEX: MF_SOURCE_READER_CURRENT_TYPE_CONSTANTS = -1i32;
pub const MF_SOURCE_READER_D3D11_BIND_FLAGS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 871569787, data2: 63290, data3: 19988, data4: [141, 133, 14, 76, 67, 104, 120, 141] };
pub const MF_SOURCE_READER_D3D_MANAGER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3967954338,
    data2: 57833,
    data3: 19241,
    data4: [160, 216, 86, 60, 113, 159, 82, 105],
};
pub const MF_SOURCE_READER_DISABLE_CAMERA_PLUGINS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2637391325,
    data2: 1423,
    data3: 19707,
    data4: [159, 151, 179, 20, 204, 153, 200, 173],
};
pub const MF_SOURCE_READER_DISABLE_DXVA: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2856676605, data2: 14659, data3: 18974, data4: [167, 125, 24, 56, 192, 234, 46, 53] };
pub const MF_SOURCE_READER_DISCONNECT_MEDIASOURCE_ON_SHUTDOWN: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1454797157, data2: 8606, data3: 17773, data4: [162, 46, 45, 48, 4, 199, 254, 86] };
pub const MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 260168236,
    data2: 46391,
    data3: 18034,
    data4: [168, 178, 166, 129, 177, 115, 7, 163],
};
pub const MF_SOURCE_READER_ENABLE_TRANSCODE_ONLY_TRANSFORMS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3755274248,
    data2: 46589,
    data3: 20088,
    data4: [174, 68, 98, 161, 230, 123, 190, 39],
};
pub const MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4214837053,
    data2: 52465,
    data3: 17134,
    data4: [187, 179, 249, 184, 69, 213, 104, 29],
};
pub type MF_SOURCE_READER_FLAG = i32;
pub const MF_SOURCE_READERF_ERROR: MF_SOURCE_READER_FLAG = 1i32;
pub const MF_SOURCE_READERF_ENDOFSTREAM: MF_SOURCE_READER_FLAG = 2i32;
pub const MF_SOURCE_READERF_NEWSTREAM: MF_SOURCE_READER_FLAG = 4i32;
pub const MF_SOURCE_READERF_NATIVEMEDIATYPECHANGED: MF_SOURCE_READER_FLAG = 16i32;
pub const MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED: MF_SOURCE_READER_FLAG = 32i32;
pub const MF_SOURCE_READERF_STREAMTICK: MF_SOURCE_READER_FLAG = 256i32;
pub const MF_SOURCE_READERF_ALLEFFECTSREMOVED: MF_SOURCE_READER_FLAG = 512i32;
pub const MF_SOURCE_READER_MEDIASOURCE_CHARACTERISTICS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1831073224,
    data2: 50647,
    data3: 19099,
    data4: [153, 113, 93, 17, 248, 188, 168, 128],
};
pub const MF_SOURCE_READER_MEDIASOURCE_CONFIG: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2424679403, data2: 852, data3: 18681, data4: [171, 181, 32, 13, 248, 56, 198, 142] };
pub const MF_SOURCE_STREAM_SUPPORTS_HW_CONNECTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2743227306,
    data2: 25364,
    data3: 17149,
    data4: [163, 206, 187, 39, 182, 133, 153, 70],
};
pub const MF_STF_VERSION_DATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 832660949,
    data2: 57191,
    data3: 16533,
    data4: [142, 68, 136, 104, 252, 32, 219, 253],
};
pub const MF_STF_VERSION_INFO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1735441721,
    data2: 61314,
    data3: 17646,
    data4: [164, 155, 147, 75, 235, 36, 174, 247],
};
pub const MF_STREAM_SINK_SUPPORTS_HW_CONNECTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2605079743, data2: 1431, data3: 20382, data4: [159, 60, 185, 126, 238, 249, 3, 89] };
pub const MF_STREAM_SINK_SUPPORTS_ROTATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3018416768,
    data2: 48389,
    data3: 16805,
    data4: [151, 173, 138, 127, 238, 36, 185, 18],
};
pub type MF_STREAM_STATE = i32;
pub const MF_STREAM_STATE_STOPPED: MF_STREAM_STATE = 0i32;
pub const MF_STREAM_STATE_PAUSED: MF_STREAM_STATE = 1i32;
pub const MF_STREAM_STATE_RUNNING: MF_STREAM_STATE = 2i32;
pub const MF_ST_MEDIASOURCE_COLLECTION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1634593138, data2: 33709, data3: 18768, data4: [129, 112, 99, 13, 25, 203, 227, 7] };
pub const MF_SYNTAX_ERR: u32 = 2154823692u32;
pub const MF_S_ACTIVATE_REPLACED: ::windows_sys::core::HRESULT = 866045i32;
pub const MF_S_ASF_PARSEINPROGRESS: ::windows_sys::core::HRESULT = 1074608792i32;
pub const MF_S_CLOCK_STOPPED: ::windows_sys::core::HRESULT = 891972i32;
pub const MF_S_MULTIPLE_BEGIN: ::windows_sys::core::HRESULT = 866008i32;
pub const MF_S_PE_TRUSTED: ::windows_sys::core::HRESULT = 881011i32;
pub const MF_S_PROTECTION_NOT_REQUIRED: ::windows_sys::core::HRESULT = 880976i32;
pub const MF_S_SEQUENCER_CONTEXT_CANCELED: ::windows_sys::core::HRESULT = 876973i32;
pub const MF_S_SEQUENCER_SEGMENT_AT_END_OF_STREAM: ::windows_sys::core::HRESULT = 876975i32;
pub const MF_S_SINK_NOT_FINALIZED: ::windows_sys::core::HRESULT = 870978i32;
pub const MF_S_TRANSFORM_DO_NOT_PROPAGATE_EVENT: ::windows_sys::core::HRESULT = 879989i32;
pub const MF_S_VIDEO_DISABLED_WITH_UNKNOWN_SOFTWARE_OUTPUT: ::windows_sys::core::HRESULT = 881001i32;
pub const MF_S_WAIT_FOR_POLICY_SET: ::windows_sys::core::HRESULT = 881000i32;
pub const MF_SampleProtectionSalt: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1409539822, data2: 47598, data3: 17295, data4: [170, 131, 56, 4, 153, 126, 86, 157] };
pub const MF_TEST_SIGNED_COMPONENT_LOADING: u32 = 16777216u32;
pub const MF_TIMECODE_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2698314407, data2: 3763, data3: 18565, data4: [177, 185, 159, 235, 13, 8, 52, 84] };
pub type MF_TIMED_TEXT_ALIGNMENT = i32;
pub const MF_TIMED_TEXT_ALIGNMENT_START: MF_TIMED_TEXT_ALIGNMENT = 0i32;
pub const MF_TIMED_TEXT_ALIGNMENT_END: MF_TIMED_TEXT_ALIGNMENT = 1i32;
pub const MF_TIMED_TEXT_ALIGNMENT_CENTER: MF_TIMED_TEXT_ALIGNMENT = 2i32;
pub type MF_TIMED_TEXT_BOUTEN_POSITION = i32;
pub const MF_TIMED_TEXT_BOUTEN_POSITION_BEFORE: MF_TIMED_TEXT_BOUTEN_POSITION = 0i32;
pub const MF_TIMED_TEXT_BOUTEN_POSITION_AFTER: MF_TIMED_TEXT_BOUTEN_POSITION = 1i32;
pub const MF_TIMED_TEXT_BOUTEN_POSITION_OUTSIDE: MF_TIMED_TEXT_BOUTEN_POSITION = 2i32;
pub type MF_TIMED_TEXT_BOUTEN_TYPE = i32;
pub const MF_TIMED_TEXT_BOUTEN_TYPE_NONE: MF_TIMED_TEXT_BOUTEN_TYPE = 0i32;
pub const MF_TIMED_TEXT_BOUTEN_TYPE_AUTO: MF_TIMED_TEXT_BOUTEN_TYPE = 1i32;
pub const MF_TIMED_TEXT_BOUTEN_TYPE_FILLEDCIRCLE: MF_TIMED_TEXT_BOUTEN_TYPE = 2i32;
pub const MF_TIMED_TEXT_BOUTEN_TYPE_OPENCIRCLE: MF_TIMED_TEXT_BOUTEN_TYPE = 3i32;
pub const MF_TIMED_TEXT_BOUTEN_TYPE_FILLEDDOT: MF_TIMED_TEXT_BOUTEN_TYPE = 4i32;
pub const MF_TIMED_TEXT_BOUTEN_TYPE_OPENDOT: MF_TIMED_TEXT_BOUTEN_TYPE = 5i32;
pub const MF_TIMED_TEXT_BOUTEN_TYPE_FILLEDSESAME: MF_TIMED_TEXT_BOUTEN_TYPE = 6i32;
pub const MF_TIMED_TEXT_BOUTEN_TYPE_OPENSESAME: MF_TIMED_TEXT_BOUTEN_TYPE = 7i32;
pub type MF_TIMED_TEXT_CUE_EVENT = i32;
pub const MF_TIMED_TEXT_CUE_EVENT_ACTIVE: MF_TIMED_TEXT_CUE_EVENT = 0i32;
pub const MF_TIMED_TEXT_CUE_EVENT_INACTIVE: MF_TIMED_TEXT_CUE_EVENT = 1i32;
pub const MF_TIMED_TEXT_CUE_EVENT_CLEAR: MF_TIMED_TEXT_CUE_EVENT = 2i32;
pub type MF_TIMED_TEXT_DECORATION = i32;
pub const MF_TIMED_TEXT_DECORATION_NONE: MF_TIMED_TEXT_DECORATION = 0i32;
pub const MF_TIMED_TEXT_DECORATION_UNDERLINE: MF_TIMED_TEXT_DECORATION = 1i32;
pub const MF_TIMED_TEXT_DECORATION_LINE_THROUGH: MF_TIMED_TEXT_DECORATION = 2i32;
pub const MF_TIMED_TEXT_DECORATION_OVERLINE: MF_TIMED_TEXT_DECORATION = 4i32;
pub type MF_TIMED_TEXT_DISPLAY_ALIGNMENT = i32;
pub const MF_TIMED_TEXT_DISPLAY_ALIGNMENT_BEFORE: MF_TIMED_TEXT_DISPLAY_ALIGNMENT = 0i32;
pub const MF_TIMED_TEXT_DISPLAY_ALIGNMENT_AFTER: MF_TIMED_TEXT_DISPLAY_ALIGNMENT = 1i32;
pub const MF_TIMED_TEXT_DISPLAY_ALIGNMENT_CENTER: MF_TIMED_TEXT_DISPLAY_ALIGNMENT = 2i32;
pub type MF_TIMED_TEXT_ERROR_CODE = i32;
pub const MF_TIMED_TEXT_ERROR_CODE_NOERROR: MF_TIMED_TEXT_ERROR_CODE = 0i32;
pub const MF_TIMED_TEXT_ERROR_CODE_FATAL: MF_TIMED_TEXT_ERROR_CODE = 1i32;
pub const MF_TIMED_TEXT_ERROR_CODE_DATA_FORMAT: MF_TIMED_TEXT_ERROR_CODE = 2i32;
pub const MF_TIMED_TEXT_ERROR_CODE_NETWORK: MF_TIMED_TEXT_ERROR_CODE = 3i32;
pub const MF_TIMED_TEXT_ERROR_CODE_INTERNAL: MF_TIMED_TEXT_ERROR_CODE = 4i32;
pub type MF_TIMED_TEXT_FONT_STYLE = i32;
pub const MF_TIMED_TEXT_FONT_STYLE_NORMAL: MF_TIMED_TEXT_FONT_STYLE = 0i32;
pub const MF_TIMED_TEXT_FONT_STYLE_OBLIQUE: MF_TIMED_TEXT_FONT_STYLE = 1i32;
pub const MF_TIMED_TEXT_FONT_STYLE_ITALIC: MF_TIMED_TEXT_FONT_STYLE = 2i32;
pub type MF_TIMED_TEXT_RUBY_ALIGN = i32;
pub const MF_TIMED_TEXT_RUBY_ALIGN_CENTER: MF_TIMED_TEXT_RUBY_ALIGN = 0i32;
pub const MF_TIMED_TEXT_RUBY_ALIGN_START: MF_TIMED_TEXT_RUBY_ALIGN = 1i32;
pub const MF_TIMED_TEXT_RUBY_ALIGN_END: MF_TIMED_TEXT_RUBY_ALIGN = 2i32;
pub const MF_TIMED_TEXT_RUBY_ALIGN_SPACEAROUND: MF_TIMED_TEXT_RUBY_ALIGN = 3i32;
pub const MF_TIMED_TEXT_RUBY_ALIGN_SPACEBETWEEN: MF_TIMED_TEXT_RUBY_ALIGN = 4i32;
pub const MF_TIMED_TEXT_RUBY_ALIGN_WITHBASE: MF_TIMED_TEXT_RUBY_ALIGN = 5i32;
pub type MF_TIMED_TEXT_RUBY_POSITION = i32;
pub const MF_TIMED_TEXT_RUBY_POSITION_BEFORE: MF_TIMED_TEXT_RUBY_POSITION = 0i32;
pub const MF_TIMED_TEXT_RUBY_POSITION_AFTER: MF_TIMED_TEXT_RUBY_POSITION = 1i32;
pub const MF_TIMED_TEXT_RUBY_POSITION_OUTSIDE: MF_TIMED_TEXT_RUBY_POSITION = 2i32;
pub type MF_TIMED_TEXT_RUBY_RESERVE = i32;
pub const MF_TIMED_TEXT_RUBY_RESERVE_NONE: MF_TIMED_TEXT_RUBY_RESERVE = 0i32;
pub const MF_TIMED_TEXT_RUBY_RESERVE_BEFORE: MF_TIMED_TEXT_RUBY_RESERVE = 1i32;
pub const MF_TIMED_TEXT_RUBY_RESERVE_AFTER: MF_TIMED_TEXT_RUBY_RESERVE = 2i32;
pub const MF_TIMED_TEXT_RUBY_RESERVE_BOTH: MF_TIMED_TEXT_RUBY_RESERVE = 3i32;
pub const MF_TIMED_TEXT_RUBY_RESERVE_OUTSIDE: MF_TIMED_TEXT_RUBY_RESERVE = 4i32;
pub type MF_TIMED_TEXT_SCROLL_MODE = i32;
pub const MF_TIMED_TEXT_SCROLL_MODE_POP_ON: MF_TIMED_TEXT_SCROLL_MODE = 0i32;
pub const MF_TIMED_TEXT_SCROLL_MODE_ROLL_UP: MF_TIMED_TEXT_SCROLL_MODE = 1i32;
pub type MF_TIMED_TEXT_TRACK_KIND = i32;
pub const MF_TIMED_TEXT_TRACK_KIND_UNKNOWN: MF_TIMED_TEXT_TRACK_KIND = 0i32;
pub const MF_TIMED_TEXT_TRACK_KIND_SUBTITLES: MF_TIMED_TEXT_TRACK_KIND = 1i32;
pub const MF_TIMED_TEXT_TRACK_KIND_CAPTIONS: MF_TIMED_TEXT_TRACK_KIND = 2i32;
pub const MF_TIMED_TEXT_TRACK_KIND_METADATA: MF_TIMED_TEXT_TRACK_KIND = 3i32;
pub type MF_TIMED_TEXT_TRACK_READY_STATE = i32;
pub const MF_TIMED_TEXT_TRACK_READY_STATE_NONE: MF_TIMED_TEXT_TRACK_READY_STATE = 0i32;
pub const MF_TIMED_TEXT_TRACK_READY_STATE_LOADING: MF_TIMED_TEXT_TRACK_READY_STATE = 1i32;
pub const MF_TIMED_TEXT_TRACK_READY_STATE_LOADED: MF_TIMED_TEXT_TRACK_READY_STATE = 2i32;
pub const MF_TIMED_TEXT_TRACK_READY_STATE_ERROR: MF_TIMED_TEXT_TRACK_READY_STATE = 3i32;
pub type MF_TIMED_TEXT_UNIT_TYPE = i32;
pub const MF_TIMED_TEXT_UNIT_TYPE_PIXELS: MF_TIMED_TEXT_UNIT_TYPE = 0i32;
pub const MF_TIMED_TEXT_UNIT_TYPE_PERCENTAGE: MF_TIMED_TEXT_UNIT_TYPE = 1i32;
pub type MF_TIMED_TEXT_WRITING_MODE = i32;
pub const MF_TIMED_TEXT_WRITING_MODE_LRTB: MF_TIMED_TEXT_WRITING_MODE = 0i32;
pub const MF_TIMED_TEXT_WRITING_MODE_RLTB: MF_TIMED_TEXT_WRITING_MODE = 1i32;
pub const MF_TIMED_TEXT_WRITING_MODE_TBRL: MF_TIMED_TEXT_WRITING_MODE = 2i32;
pub const MF_TIMED_TEXT_WRITING_MODE_TBLR: MF_TIMED_TEXT_WRITING_MODE = 3i32;
pub const MF_TIMED_TEXT_WRITING_MODE_LR: MF_TIMED_TEXT_WRITING_MODE = 4i32;
pub const MF_TIMED_TEXT_WRITING_MODE_RL: MF_TIMED_TEXT_WRITING_MODE = 5i32;
pub const MF_TIMED_TEXT_WRITING_MODE_TB: MF_TIMED_TEXT_WRITING_MODE = 6i32;
pub const MF_TIME_FORMAT_ENTRY_RELATIVE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1134162296,
    data2: 18131,
    data3: 17668,
    data4: [175, 218, 32, 211, 46, 155, 163, 96],
};
pub const MF_TIME_FORMAT_SEGMENT_OFFSET: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3367550583, data2: 34460, data3: 17181, data4: [129, 46, 22, 150, 147, 246, 90, 57] };
pub const MF_TOPOLOGY_DXVA_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 512570614,
    data2: 62891,
    data3: 20003,
    data4: [187, 136, 135, 74, 163, 161, 167, 77],
};
pub const MF_TOPOLOGY_DYNAMIC_CHANGE_NOT_ALLOWED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3576272139,
    data2: 54404,
    data3: 17703,
    data4: [169, 205, 177, 144, 149, 50, 181, 176],
};
pub const MF_TOPOLOGY_ENABLE_XVP_FOR_PLAYBACK: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 426210079, data2: 52600, data3: 17148, data4: [176, 38, 9, 146, 165, 110, 86, 147] };
pub const MF_TOPOLOGY_ENUMERATE_SOURCE_TYPES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1648935789,
    data2: 23819,
    data3: 20288,
    data4: [160, 187, 176, 179, 5, 247, 118, 152],
};
pub const MF_TOPOLOGY_HARDWARE_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3537068797,
    data2: 20047,
    data3: 16785,
    data4: [165, 121, 198, 24, 182, 103, 6, 175],
};
pub const MF_TOPOLOGY_NO_MARKIN_MARKOUT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2127820804,
    data2: 34491,
    data3: 19263,
    data4: [183, 228, 124, 180, 58, 253, 75, 128],
};
pub const MF_TOPOLOGY_PLAYBACK_FRAMERATE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3244585850, data2: 49841, data3: 17747, data4: [131, 187, 90, 82, 96, 114, 68, 143] };
pub const MF_TOPOLOGY_PLAYBACK_MAX_DIMS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1461047065,
    data2: 22376,
    data3: 17578,
    data4: [173, 110, 135, 33, 241, 176, 249, 187],
};
pub const MF_TOPOLOGY_PROJECTSTART: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2127820802,
    data2: 34491,
    data3: 19263,
    data4: [183, 228, 124, 180, 58, 253, 75, 128],
};
pub const MF_TOPOLOGY_PROJECTSTOP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2127820803,
    data2: 34491,
    data3: 19263,
    data4: [183, 228, 124, 180, 58, 253, 75, 128],
};
pub const MF_TOPOLOGY_RESOLUTION_STATUS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700318,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub type MF_TOPOLOGY_RESOLUTION_STATUS_FLAGS = i32;
pub const MF_TOPOLOGY_RESOLUTION_SUCCEEDED: MF_TOPOLOGY_RESOLUTION_STATUS_FLAGS = 0i32;
pub const MF_OPTIONAL_NODE_REJECTED_MEDIA_TYPE: MF_TOPOLOGY_RESOLUTION_STATUS_FLAGS = 1i32;
pub const MF_OPTIONAL_NODE_REJECTED_PROTECTED_PROCESS: MF_TOPOLOGY_RESOLUTION_STATUS_FLAGS = 2i32;
pub const MF_TOPOLOGY_START_TIME_ON_PRESENTATION_SWITCH: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3368816959,
    data2: 31057,
    data3: 17736,
    data4: [170, 214, 158, 214, 32, 46, 98, 179],
};
pub const MF_TOPOLOGY_STATIC_PLAYBACK_OPTIMIZATIONS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3094129730, data2: 16806, data3: 19321, data4: [137, 122, 26, 176, 229, 43, 74, 27] };
pub type MF_TOPOLOGY_TYPE = i32;
pub const MF_TOPOLOGY_OUTPUT_NODE: MF_TOPOLOGY_TYPE = 0i32;
pub const MF_TOPOLOGY_SOURCESTREAM_NODE: MF_TOPOLOGY_TYPE = 1i32;
pub const MF_TOPOLOGY_TRANSFORM_NODE: MF_TOPOLOGY_TYPE = 2i32;
pub const MF_TOPOLOGY_TEE_NODE: MF_TOPOLOGY_TYPE = 3i32;
pub const MF_TOPOLOGY_MAX: MF_TOPOLOGY_TYPE = -1i32;
pub const MF_TOPONODE_ATTRIBUTE_EDITOR_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1701146138, data2: 1919, data3: 17522, data4: [131, 239, 49, 111, 17, 213, 8, 122] };
pub const MF_TOPONODE_CONNECT_METHOD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700337,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_D3DAWARE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700333,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_DECODER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700354,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_DECRYPTOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700346,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_DISABLE_PREROLL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 345190302, data2: 36999, data3: 19380, data4: [132, 18, 81, 103, 20, 92, 190, 4] };
pub const MF_TOPONODE_DISCARDABLE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700347,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_DRAIN: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700329,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub type MF_TOPONODE_DRAIN_MODE = i32;
pub const MF_TOPONODE_DRAIN_DEFAULT: MF_TOPONODE_DRAIN_MODE = 0i32;
pub const MF_TOPONODE_DRAIN_ALWAYS: MF_TOPONODE_DRAIN_MODE = 1i32;
pub const MF_TOPONODE_DRAIN_NEVER: MF_TOPONODE_DRAIN_MODE = 2i32;
pub const MF_TOPONODE_ERRORCODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700334,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_ERROR_MAJORTYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700349,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_ERROR_SUBTYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700350,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_FLUSH: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700328,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub type MF_TOPONODE_FLUSH_MODE = i32;
pub const MF_TOPONODE_FLUSH_ALWAYS: MF_TOPONODE_FLUSH_MODE = 0i32;
pub const MF_TOPONODE_FLUSH_SEEK: MF_TOPONODE_FLUSH_MODE = 1i32;
pub const MF_TOPONODE_FLUSH_NEVER: MF_TOPONODE_FLUSH_MODE = 2i32;
pub const MF_TOPONODE_LOCKED: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700343,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_MARKIN_HERE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700352,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_MARKOUT_HERE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700353,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_MEDIASTART: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2203867370,
    data2: 57461,
    data3: 19399,
    data4: [188, 186, 77, 224, 0, 223, 154, 230],
};
pub const MF_TOPONODE_MEDIASTOP: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2203867371,
    data2: 57461,
    data3: 19399,
    data4: [188, 186, 77, 224, 0, 223, 154, 230],
};
pub const MF_TOPONODE_NOSHUTDOWN_ON_REMOVE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 345190300, data2: 36999, data3: 19380, data4: [132, 18, 81, 103, 20, 92, 190, 4] };
pub const MF_TOPONODE_PRESENTATION_DESCRIPTOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2203867373,
    data2: 57461,
    data3: 19399,
    data4: [188, 186, 77, 224, 0, 223, 154, 230],
};
pub const MF_TOPONODE_PRIMARYOUTPUT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1661267865,
    data2: 5810,
    data3: 20158,
    data4: [157, 103, 228, 197, 57, 179, 162, 89],
};
pub const MF_TOPONODE_RATELESS: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 345190301, data2: 36999, data3: 19380, data4: [132, 18, 81, 103, 20, 92, 190, 4] };
pub const MF_TOPONODE_SEQUENCE_ELEMENTID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2203867375,
    data2: 57461,
    data3: 19399,
    data4: [188, 186, 77, 224, 0, 223, 154, 230],
};
pub const MF_TOPONODE_SOURCE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2203867372,
    data2: 57461,
    data3: 19399,
    data4: [188, 186, 77, 224, 0, 223, 154, 230],
};
pub const MF_TOPONODE_STREAMID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 345190299, data2: 36999, data3: 19380, data4: [132, 18, 81, 103, 20, 92, 190, 4] };
pub const MF_TOPONODE_STREAM_DESCRIPTOR: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2203867374,
    data2: 57461,
    data3: 19399,
    data4: [188, 186, 77, 224, 0, 223, 154, 230],
};
pub const MF_TOPONODE_TRANSFORM_OBJECTID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2296168649,
    data2: 10558,
    data3: 20107,
    data4: [154, 235, 10, 214, 76, 192, 22, 176],
};
pub const MF_TOPONODE_WORKQUEUE_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700344,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_WORKQUEUE_ITEM_PRIORITY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2717882814,
    data2: 24215,
    data3: 19027,
    data4: [180, 148, 86, 140, 100, 44, 15, 243],
};
pub const MF_TOPONODE_WORKQUEUE_MMCSS_CLASS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700345,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub const MF_TOPONODE_WORKQUEUE_MMCSS_PRIORITY: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1342306368,
    data2: 10262,
    data3: 18676,
    data4: [147, 100, 173, 30, 246, 97, 161, 35],
};
pub const MF_TOPONODE_WORKQUEUE_MMCSS_TASKID: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1229700351,
    data2: 45105,
    data3: 20024,
    data4: [151, 196, 213, 66, 45, 214, 24, 220],
};
pub type MF_TOPOSTATUS = i32;
pub const MF_TOPOSTATUS_INVALID: MF_TOPOSTATUS = 0i32;
pub const MF_TOPOSTATUS_READY: MF_TOPOSTATUS = 100i32;
pub const MF_TOPOSTATUS_STARTED_SOURCE: MF_TOPOSTATUS = 200i32;
pub const MF_TOPOSTATUS_DYNAMIC_CHANGED: MF_TOPOSTATUS = 210i32;
pub const MF_TOPOSTATUS_SINK_SWITCHED: MF_TOPOSTATUS = 300i32;
pub const MF_TOPOSTATUS_ENDED: MF_TOPOSTATUS = 400i32;
pub const MF_TRANSCODE_ADJUST_PROFILE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2620899867,
    data2: 1551,
    data3: 18556,
    data4: [166, 144, 128, 215, 245, 13, 28, 114],
};
pub type MF_TRANSCODE_ADJUST_PROFILE_FLAGS = i32;
pub const MF_TRANSCODE_ADJUST_PROFILE_DEFAULT: MF_TRANSCODE_ADJUST_PROFILE_FLAGS = 0i32;
pub const MF_TRANSCODE_ADJUST_PROFILE_USE_SOURCE_ATTRIBUTES: MF_TRANSCODE_ADJUST_PROFILE_FLAGS = 1i32;
pub const MF_TRANSCODE_CONTAINERTYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 353366591,
    data2: 19132,
    data3: 18315,
    data4: [172, 79, 225, 145, 111, 186, 28, 202],
};
pub const MF_TRANSCODE_DONOT_INSERT_ENCODER: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4099581902, data2: 43812, data3: 16402, data4: [161, 27, 220, 130, 32, 32, 20, 16] };
pub const MF_TRANSCODE_ENCODINGPROFILE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1766291580,
    data2: 62728,
    data3: 20137,
    data4: [177, 233, 161, 254, 58, 73, 251, 201],
};
pub const MF_TRANSCODE_QUALITYVSSPEED: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2553490936, data2: 973, data3: 18283, data4: [137, 250, 63, 158, 68, 45, 236, 159] };
#[repr(C)]
pub struct MF_TRANSCODE_SINK_INFO {
    pub dwVideoStreamID: u32,
    pub pVideoMediaType: IMFMediaType,
    pub dwAudioStreamID: u32,
    pub pAudioMediaType: IMFMediaType,
}
impl ::core::marker::Copy for MF_TRANSCODE_SINK_INFO {}
impl ::core::clone::Clone for MF_TRANSCODE_SINK_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MF_TRANSCODE_SKIP_METADATA_TRANSFER: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1313106415,
    data2: 46449,
    data3: 18777,
    data4: [143, 131, 61, 207, 186, 51, 163, 147],
};
pub const MF_TRANSCODE_TOPOLOGYMODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1044248080,
    data2: 14666,
    data3: 16562,
    data4: [157, 234, 59, 171, 101, 11, 235, 242],
};
pub type MF_TRANSCODE_TOPOLOGYMODE_FLAGS = i32;
pub const MF_TRANSCODE_TOPOLOGYMODE_SOFTWARE_ONLY: MF_TRANSCODE_TOPOLOGYMODE_FLAGS = 0i32;
pub const MF_TRANSCODE_TOPOLOGYMODE_HARDWARE_ALLOWED: MF_TRANSCODE_TOPOLOGYMODE_FLAGS = 1i32;
pub const MF_TRANSFORM_ASYNC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4162480538,
    data2: 25754,
    data3: 18813,
    data4: [140, 115, 41, 248, 254, 214, 173, 122],
};
pub const MF_TRANSFORM_ASYNC_UNLOCK: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3848695147,
    data2: 13346,
    data3: 20150,
    data4: [164, 33, 218, 125, 177, 248, 226, 7],
};
pub const MF_TRANSFORM_CATEGORY_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3467360841,
    data2: 20589,
    data3: 18263,
    data4: [166, 255, 102, 193, 132, 152, 126, 78],
};
pub const MF_TRANSFORM_FLAGS_Attribute: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2472131454, data2: 25205, data3: 18116, data4: [160, 37, 28, 1, 228, 95, 26, 134] };
pub const MF_TYPE_ERR: u32 = 2154840069u32;
pub const MF_UNKNOWN_DURATION: u32 = 0u32;
pub type MF_URL_TRUST_STATUS = i32;
pub const MF_LICENSE_URL_UNTRUSTED: MF_URL_TRUST_STATUS = 0i32;
pub const MF_LICENSE_URL_TRUSTED: MF_URL_TRUST_STATUS = 1i32;
pub const MF_LICENSE_URL_TAMPERED: MF_URL_TRUST_STATUS = 2i32;
pub const MF_USER_DATA_PAYLOAD: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3520370781, data2: 56466, data3: 17786, data4: [179, 160, 101, 26, 51, 163, 16, 71] };
pub const MF_USER_EXTENDED_ATTRIBUTES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3224025798, data2: 65202, data3: 17729, data4: [146, 47, 146, 11, 67, 112, 39, 34] };
pub const MF_USER_MODE_COMPONENT_LOAD: u32 = 1u32;
pub const MF_VIDEODSP_MODE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 383197424, data2: 30348, data3: 4574, data4: [138, 57, 8, 0, 32, 12, 154, 102] };
pub const MF_VIDEO_MAX_MB_PER_SEC: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3824345603, data2: 54341, data3: 19340, data4: [146, 17, 174, 57, 13, 59, 160, 23] };
pub const MF_VIDEO_PROCESSOR_ALGORITHM: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1242177055,
    data2: 10028,
    data3: 20406,
    data4: [158, 177, 219, 51, 12, 188, 151, 202],
};
pub type MF_VIDEO_PROCESSOR_ALGORITHM_TYPE = i32;
pub const MF_VIDEO_PROCESSOR_ALGORITHM_DEFAULT: MF_VIDEO_PROCESSOR_ALGORITHM_TYPE = 0i32;
pub const MF_VIDEO_PROCESSOR_ALGORITHM_MRF_CRF_444: MF_VIDEO_PROCESSOR_ALGORITHM_TYPE = 1i32;
pub type MF_VIDEO_PROCESSOR_MIRROR = i32;
pub const MIRROR_NONE: MF_VIDEO_PROCESSOR_MIRROR = 0i32;
pub const MIRROR_HORIZONTAL: MF_VIDEO_PROCESSOR_MIRROR = 1i32;
pub const MIRROR_VERTICAL: MF_VIDEO_PROCESSOR_MIRROR = 2i32;
pub type MF_VIDEO_PROCESSOR_ROTATION = i32;
pub const ROTATION_NONE: MF_VIDEO_PROCESSOR_ROTATION = 0i32;
pub const ROTATION_NORMAL: MF_VIDEO_PROCESSOR_ROTATION = 1i32;
pub const MF_VIDEO_RENDERER_EFFECT_APP_SERVICE_NAME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 3322227328,
    data2: 28060,
    data3: 16547,
    data4: [157, 184, 240, 39, 162, 92, 154, 185],
};
#[repr(C)]
pub struct MF_VIDEO_SPHERICAL_VIEWDIRECTION {
    pub iHeading: i32,
    pub iPitch: i32,
    pub iRoll: i32,
}
impl ::core::marker::Copy for MF_VIDEO_SPHERICAL_VIEWDIRECTION {}
impl ::core::clone::Clone for MF_VIDEO_SPHERICAL_VIEWDIRECTION {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MF_VIRTUALCAMERA_CONFIGURATION_APP_PACKAGE_FAMILY_NAME: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1703591505,
    data2: 32836,
    data3: 17966,
    data4: [151, 234, 230, 118, 253, 114, 5, 95],
};
pub const MF_WORKQUEUE_SERVICES: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2386023561,
    data2: 16864,
    data3: 16698,
    data4: [144, 104, 40, 124, 136, 109, 141, 218],
};
pub const MF_WRAPPED_BUFFER_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2874425458, data2: 49769, data3: 20156, data4: [165, 82, 28, 59, 50, 190, 213, 202] };
pub const MF_WRAPPED_OBJECT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 723004492,
    data2: 54956,
    data3: 18932,
    data4: [137, 21, 247, 24, 135, 219, 112, 205],
};
pub const MF_WRAPPED_SAMPLE_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 838151154, data2: 53310, data3: 16456, data4: [128, 208, 156, 16, 70, 216, 124, 97] };
pub const MF_WVC1_PROG_SINGLE_SLICE_CONTENT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1743529305,
    data2: 3887,
    data3: 17440,
    data4: [164, 221, 47, 142, 231, 165, 115, 139],
};
pub const MF_XVP_CALLER_ALLOCATES_OUTPUT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 77777596, data2: 3243, data3: 16561, data4: [161, 185, 117, 188, 54, 88, 240, 0] };
pub const MF_XVP_DISABLE_FRC: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 738916889,
    data2: 31383,
    data3: 19802,
    data4: [158, 232, 22, 212, 252, 81, 141, 140],
};
pub const MF_XVP_SAMPLE_LOCK_TIMEOUT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2857229097, data2: 20788, data3: 17251, data4: [172, 114, 131, 236, 75, 193, 4, 38] };
pub type MIC_ARRAY_MODE = i32;
pub const MICARRAY_SINGLE_CHAN: MIC_ARRAY_MODE = 0i32;
pub const MICARRAY_SIMPLE_SUM: MIC_ARRAY_MODE = 256i32;
pub const MICARRAY_SINGLE_BEAM: MIC_ARRAY_MODE = 512i32;
pub const MICARRAY_FIXED_BEAM: MIC_ARRAY_MODE = 1024i32;
pub const MICARRAY_EXTERN_BEAM: MIC_ARRAY_MODE = 2048i32;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MOVEREGION_INFO {
    pub FrameNumber: u32,
    pub NumMoveRegions: u32,
    pub MoveRegions: [MOVE_RECT; 1],
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MOVEREGION_INFO {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MOVEREGION_INFO {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MOVE_RECT {
    pub SourcePoint: super::super::Foundation::POINT,
    pub DestRect: super::super::Foundation::RECT,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MOVE_RECT {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MOVE_RECT {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MP3ACMCodecWrapper: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 286274593, data2: 13644, data3: 19658, data4: [167, 163, 26, 255, 154, 91, 103, 1] };
pub const MR_AUDIO_POLICY_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2434783031,
    data2: 26485,
    data3: 19120,
    data4: [166, 20, 41, 120, 98, 253, 172, 136],
};
pub const MR_BUFFER_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2774672524,
    data2: 39622,
    data3: 20476,
    data4: [159, 186, 58, 248, 248, 173, 26, 77],
};
pub const MR_CAPTURE_POLICY_VOLUME_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 604179149, data2: 4218, data3: 16997, data4: [151, 92, 65, 78, 51, 230, 95, 42] };
pub const MR_POLICY_VOLUME_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 448438956, data2: 40251, data3: 18374, data4: [171, 72, 197, 149, 6, 222, 120, 77] };
pub const MR_STREAM_VOLUME_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 4172675631, data2: 13039, data3: 18165, data4: [177, 114, 19, 33, 33, 47, 178, 196] };
pub const MR_VIDEO_ACCELERATION_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 4025438581,
    data2: 23677,
    data3: 19682,
    data4: [187, 189, 52, 255, 139, 202, 101, 84],
};
pub const MR_VIDEO_MIXER_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 121426684, data2: 27892, data3: 16567, data4: [136, 89, 232, 149, 82, 200, 65, 248] };
pub const MR_VIDEO_RENDER_SERVICE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 278046828, data2: 43802, data3: 17818, data4: [163, 54, 131, 31, 188, 77, 17, 255] };
pub const MSAMRNBDecoder: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 642781614,
    data2: 21633,
    data3: 20343,
    data4: [162, 149, 171, 182, 255, 232, 214, 62],
};
pub const MSAMRNBEncoder: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 799967998, data2: 1187, data3: 16954, data4: [168, 20, 133, 219, 69, 71, 18, 176] };
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct MT_ARBITRARY_HEADER {
    pub majortype: ::windows_sys::core::GUID,
    pub subtype: ::windows_sys::core::GUID,
    pub bFixedSizeSamples: super::super::Foundation::BOOL,
    pub bTemporalCompression: super::super::Foundation::BOOL,
    pub lSampleSize: u32,
    pub formattype: ::windows_sys::core::GUID,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for MT_ARBITRARY_HEADER {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for MT_ARBITRARY_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct MT_CUSTOM_VIDEO_PRIMARIES {
    pub fRx: f32,
    pub fRy: f32,
    pub fGx: f32,
    pub fGy: f32,
    pub fBx: f32,
    pub fBy: f32,
    pub fWx: f32,
    pub fWy: f32,
}
impl ::core::marker::Copy for MT_CUSTOM_VIDEO_PRIMARIES {}
impl ::core::clone::Clone for MT_CUSTOM_VIDEO_PRIMARIES {
    fn clone(&self) -> Self {
        *self
    }
}
pub const MULawCodecWrapper: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2461425792, data2: 24109, data3: 17566, data4: [144, 196, 196, 31, 38, 142, 85, 20] };
#[repr(C, packed(1))]
pub struct OPM_ACP_AND_CGMSA_SIGNALING {
    pub rnRandomNumber: OPM_RANDOM_NUMBER,
    pub ulStatusFlags: u32,
    pub ulAvailableTVProtectionStandards: u32,
    pub ulActiveTVProtectionStandard: u32,
    pub ulReserved: u32,
    pub ulAspectRatioValidMask1: u32,
    pub ulAspectRatioData1: u32,
    pub ulAspectRatioValidMask2: u32,
    pub ulAspectRatioData2: u32,
    pub ulAspectRatioValidMask3: u32,
    pub ulAspectRatioData3: u32,
    pub ulReserved2: [u32; 4],
    pub ulReserved3: [u32; 4],
}
impl ::core::marker::Copy for OPM_ACP_AND_CGMSA_SIGNALING {}
impl ::core::clone::Clone for OPM_ACP_AND_CGMSA_SIGNALING {
    fn clone(&self) -> Self {
        *self
    }
}
pub type OPM_ACP_PROTECTION_LEVEL = i32;
pub const OPM_ACP_OFF: OPM_ACP_PROTECTION_LEVEL = 0i32;
pub const OPM_ACP_LEVEL_ONE: OPM_ACP_PROTECTION_LEVEL = 1i32;
pub const OPM_ACP_LEVEL_TWO: OPM_ACP_PROTECTION_LEVEL = 2i32;
pub const OPM_ACP_LEVEL_THREE: OPM_ACP_PROTECTION_LEVEL = 3i32;
pub const OPM_ACP_FORCE_ULONG: OPM_ACP_PROTECTION_LEVEL = 2147483647i32;
#[repr(C, packed(1))]
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub struct OPM_ACTUAL_OUTPUT_FORMAT {
    pub rnRandomNumber: OPM_RANDOM_NUMBER,
    pub ulStatusFlags: u32,
    pub ulDisplayWidth: u32,
    pub ulDisplayHeight: u32,
    pub dsfSampleInterleaveFormat: DXVA2_SampleFormat,
    pub d3dFormat: super::super::Graphics::Direct3D9::D3DFORMAT,
    pub ulFrequencyNumerator: u32,
    pub ulFrequencyDenominator: u32,
}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::marker::Copy for OPM_ACTUAL_OUTPUT_FORMAT {}
#[cfg(feature = "Win32_Graphics_Direct3D9")]
impl ::core::clone::Clone for OPM_ACTUAL_OUTPUT_FORMAT {
    fn clone(&self) -> Self {
        *self
    }
}
pub type OPM_BUS_TYPE = i32;
pub const OPM_BUS_TYPE_OTHER: OPM_BUS_TYPE = 0i32;
pub const OPM_BUS_TYPE_PCI: OPM_BUS_TYPE = 1i32;
pub const OPM_BUS_TYPE_PCIX: OPM_BUS_TYPE = 2i32;
pub const OPM_BUS_TYPE_PCIEXPRESS: OPM_BUS_TYPE = 3i32;
pub const OPM_BUS_TYPE_AGP: OPM_BUS_TYPE = 4i32;
pub const OPM_BUS_IMPLEMENTATION_MODIFIER_INSIDE_OF_CHIPSET: OPM_BUS_TYPE = 65536i32;
pub const OPM_BUS_IMPLEMENTATION_MODIFIER_TRACKS_ON_MOTHER_BOARD_TO_CHIP: OPM_BUS_TYPE = 131072i32;
pub const OPM_BUS_IMPLEMENTATION_MODIFIER_TRACKS_ON_MOTHER_BOARD_TO_SOCKET: OPM_BUS_TYPE = 196608i32;
pub const OPM_BUS_IMPLEMENTATION_MODIFIER_DAUGHTER_BOARD_CONNECTOR: OPM_BUS_TYPE = 262144i32;
pub const OPM_BUS_IMPLEMENTATION_MODIFIER_DAUGHTER_BOARD_CONNECTOR_INSIDE_OF_NUAE: OPM_BUS_TYPE = 327680i32;
pub const OPM_BUS_IMPLEMENTATION_MODIFIER_NON_STANDARD: OPM_BUS_TYPE = -2147483648i32;
pub const OPM_COPP_COMPATIBLE_BUS_TYPE_INTEGRATED: OPM_BUS_TYPE = -2147483648i32;
pub type OPM_CGMSA = i32;
pub const OPM_CGMSA_OFF: OPM_CGMSA = 0i32;
pub const OPM_CGMSA_COPY_FREELY: OPM_CGMSA = 1i32;
pub const OPM_CGMSA_COPY_NO_MORE: OPM_CGMSA = 2i32;
pub const OPM_CGMSA_COPY_ONE_GENERATION: OPM_CGMSA = 3i32;
pub const OPM_CGMSA_COPY_NEVER: OPM_CGMSA = 4i32;
pub const OPM_CGMSA_REDISTRIBUTION_CONTROL_REQUIRED: OPM_CGMSA = 8i32;
#[repr(C, packed(1))]
pub struct OPM_CONFIGURE_PARAMETERS {
    pub omac: OPM_OMAC,
    pub guidSetting: ::windows_sys::core::GUID,
    pub ulSequenceNumber: u32,
    pub cbParametersSize: u32,
    pub abParameters: [u8; 4056],
}
impl ::core::marker::Copy for OPM_CONFIGURE_PARAMETERS {}
impl ::core::clone::Clone for OPM_CONFIGURE_PARAMETERS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C, packed(1))]
pub struct OPM_CONNECTED_HDCP_DEVICE_INFORMATION {
    pub rnRandomNumber: OPM_RANDOM_NUMBER,
    pub ulStatusFlags: u32,
    pub ulHDCPFlags: u32,
    pub ksvB: OPM_HDCP_KEY_SELECTION_VECTOR,
    pub Reserved: [u8; 11],
    pub Reserved2: [u8; 16],
    pub Reserved3: [u8; 16],
}
impl ::core::marker::Copy for OPM_CONNECTED_HDCP_DEVICE_INFORMATION {}
impl ::core::clone::Clone for OPM_CONNECTED_HDCP_DEVICE_INFORMATION {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C, packed(1))]
pub struct OPM_COPP_COMPATIBLE_GET_INFO_PARAMETERS {
    pub rnRandomNumber: OPM_RANDOM_NUMBER,
    pub guidInformation: ::windows_sys::core::GUID,
    pub ulSequenceNumber: u32,
    pub cbParametersSize: u32,
    pub abParameters: [u8; 4056],
}
impl ::core::marker::Copy for OPM_COPP_COMPATIBLE_GET_INFO_PARAMETERS {}
impl ::core::clone::Clone for OPM_COPP_COMPATIBLE_GET_INFO_PARAMETERS {
    fn clone(&self) -> Self {
        *self
    }
}
pub type OPM_DPCP_PROTECTION_LEVEL = i32;
pub const OPM_DPCP_OFF: OPM_DPCP_PROTECTION_LEVEL = 0i32;
pub const OPM_DPCP_ON: OPM_DPCP_PROTECTION_LEVEL = 1i32;
pub const OPM_DPCP_FORCE_ULONG: OPM_DPCP_PROTECTION_LEVEL = 2147483647i32;
pub type OPM_DVI_CHARACTERISTIC = i32;
pub const OPM_DVI_CHARACTERISTIC_1_0: OPM_DVI_CHARACTERISTIC = 1i32;
pub const OPM_DVI_CHARACTERISTIC_1_1_OR_ABOVE: OPM_DVI_CHARACTERISTIC = 2i32;
#[repr(C)]
pub struct OPM_ENCRYPTED_INITIALIZATION_PARAMETERS {
    pub abEncryptedInitializationParameters: [u8; 256],
}
impl ::core::marker::Copy for OPM_ENCRYPTED_INITIALIZATION_PARAMETERS {}
impl ::core::clone::Clone for OPM_ENCRYPTED_INITIALIZATION_PARAMETERS {
    fn clone(&self) -> Self {
        *self
    }
}
pub const OPM_GET_ACP_AND_CGMSA_SIGNALING: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1714005393,
    data2: 15225,
    data3: 19699,
    data4: [146, 74, 17, 232, 231, 129, 22, 113],
};
pub const OPM_GET_ACTUAL_OUTPUT_FORMAT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3619625891, data2: 44307, data3: 20366, data4: [175, 152, 13, 203, 60, 162, 4, 204] };
pub const OPM_GET_ACTUAL_PROTECTION_LEVEL: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 425140490,
    data2: 30566,
    data3: 17706,
    data4: [185, 154, 210, 122, 237, 84, 240, 58],
};
pub const OPM_GET_ADAPTER_BUS_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 3337934451, data2: 24948, data3: 16772, data4: [142, 53, 246, 219, 82, 0, 188, 186] };
pub const OPM_GET_CODEC_INFO: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 1329022097,
    data2: 36703,
    data3: 17477,
    data4: [157, 186, 149, 88, 143, 107, 88, 180],
};
#[repr(C, packed(1))]
pub struct OPM_GET_CODEC_INFO_INFORMATION {
    pub rnRandomNumber: OPM_RANDOM_NUMBER,
    pub Merit: u32,
}
impl ::core::marker::Copy for OPM_GET_CODEC_INFO_INFORMATION {}
impl ::core::clone::Clone for OPM_GET_CODEC_INFO_INFORMATION {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C, packed(1))]
pub struct OPM_GET_CODEC_INFO_PARAMETERS {
    pub cbVerifier: u32,
    pub Verifier: [u8; 4052],
}
impl ::core::marker::Copy for OPM_GET_CODEC_INFO_PARAMETERS {}
impl ::core::clone::Clone for OPM_GET_CODEC_INFO_PARAMETERS {
    fn clone(&self) -> Self {
        *self
    }
}
pub const OPM_GET_CONNECTED_HDCP_DEVICE_INFORMATION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 230006132, data2: 43410, data3: 18734, data4: [160, 189, 194, 63, 218, 86, 78, 0] };
pub const OPM_GET_CONNECTOR_TYPE: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2177941461,
    data2: 27390,
    data3: 18626,
    data4: [153, 192, 149, 160, 143, 151, 197, 218],
};
pub const OPM_GET_CURRENT_HDCP_SRM_VERSION: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2579877631, data2: 24349, data3: 18553, data4: [129, 193, 197, 36, 67, 201, 72, 43] };
pub const OPM_GET_DVI_CHARACTERISTICS: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2758849467,
    data2: 24023,
    data3: 16754,
    data4: [131, 156, 61, 55, 118, 224, 235, 245],
};
#[repr(C, packed(1))]
pub struct OPM_GET_INFO_PARAMETERS {
    pub omac: OPM_OMAC,
    pub rnRandomNumber: OPM_RANDOM_NUMBER,
    pub guidInformation: ::windows_sys::core::GUID,
    pub ulSequenceNumber: u32,
    pub cbParametersSize: u32,
    pub abParameters: [u8; 4056],
}
impl ::core::marker::Copy for OPM_GET_INFO_PARAMETERS {}
impl ::core::clone::Clone for OPM_GET_INFO_PARAMETERS {
    fn clone(&self) -> Self {
        *self
    }
}
pub const OPM_GET_OUTPUT_HARDWARE_PROTECTION_SUPPORT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 991073673, data2: 11000, data3: 20208, data4: [150, 162, 112, 74, 132, 90, 33, 142] };
pub const OPM_GET_OUTPUT_ID: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 1925934579, data2: 9295, data3: 16590, data4: [176, 158, 32, 80, 106, 246, 48, 47] };
pub const OPM_GET_SUPPORTED_PROTECTION_TYPES: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 955426817, data2: 39532, data3: 18619, data4: [145, 7, 182, 105, 110, 111, 23, 151] };
pub const OPM_GET_VIRTUAL_PROTECTION_LEVEL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2986825815, data2: 16090, data3: 19805, data4: [136, 219, 116, 143, 140, 26, 5, 73] };
pub type OPM_HDCP_FLAGS = u32;
pub const OPM_HDCP_FLAG_NONE: OPM_HDCP_FLAGS = 0u32;
pub const OPM_HDCP_FLAG_REPEATER: OPM_HDCP_FLAGS = 1u32;
#[repr(C)]
pub struct OPM_HDCP_KEY_SELECTION_VECTOR {
    pub abKeySelectionVector: [u8; 5],
}
impl ::core::marker::Copy for OPM_HDCP_KEY_SELECTION_VECTOR {}
impl ::core::clone::Clone for OPM_HDCP_KEY_SELECTION_VECTOR {
    fn clone(&self) -> Self {
        *self
    }
}
pub type OPM_HDCP_PROTECTION_LEVEL = i32;
pub const OPM_HDCP_OFF: OPM_HDCP_PROTECTION_LEVEL = 0i32;
pub const OPM_HDCP_ON: OPM_HDCP_PROTECTION_LEVEL = 1i32;
pub const OPM_HDCP_FORCE_ULONG: OPM_HDCP_PROTECTION_LEVEL = 2147483647i32;
pub type OPM_HDCP_STATUS = i32;
pub const OPM_HDCP_STATUS_ON: OPM_HDCP_STATUS = 0i32;
pub const OPM_HDCP_STATUS_OFF: OPM_HDCP_STATUS = 1i32;
pub type OPM_HDCP_TYPE = i32;
pub const OPM_HDCP_TYPE_0: OPM_HDCP_TYPE = 0i32;
pub const OPM_HDCP_TYPE_1: OPM_HDCP_TYPE = 1i32;
pub type OPM_IMAGE_ASPECT_RATIO_EN300294 = i32;
pub const OPM_ASPECT_RATIO_EN300294_FULL_FORMAT_4_BY_3: OPM_IMAGE_ASPECT_RATIO_EN300294 = 0i32;
pub const OPM_ASPECT_RATIO_EN300294_BOX_14_BY_9_CENTER: OPM_IMAGE_ASPECT_RATIO_EN300294 = 1i32;
pub const OPM_ASPECT_RATIO_EN300294_BOX_14_BY_9_TOP: OPM_IMAGE_ASPECT_RATIO_EN300294 = 2i32;
pub const OPM_ASPECT_RATIO_EN300294_BOX_16_BY_9_CENTER: OPM_IMAGE_ASPECT_RATIO_EN300294 = 3i32;
pub const OPM_ASPECT_RATIO_EN300294_BOX_16_BY_9_TOP: OPM_IMAGE_ASPECT_RATIO_EN300294 = 4i32;
pub const OPM_ASPECT_RATIO_EN300294_BOX_GT_16_BY_9_CENTER: OPM_IMAGE_ASPECT_RATIO_EN300294 = 5i32;
pub const OPM_ASPECT_RATIO_EN300294_FULL_FORMAT_4_BY_3_PROTECTED_CENTER: OPM_IMAGE_ASPECT_RATIO_EN300294 = 6i32;
pub const OPM_ASPECT_RATIO_EN300294_FULL_FORMAT_16_BY_9_ANAMORPHIC: OPM_IMAGE_ASPECT_RATIO_EN300294 = 7i32;
pub const OPM_ASPECT_RATIO_FORCE_ULONG: OPM_IMAGE_ASPECT_RATIO_EN300294 = 2147483647i32;
#[repr(C)]
pub struct OPM_OMAC {
    pub abOMAC: [u8; 16],
}
impl ::core::marker::Copy for OPM_OMAC {}
impl ::core::clone::Clone for OPM_OMAC {
    fn clone(&self) -> Self {
        *self
    }
}
pub type OPM_OUTPUT_HARDWARE_PROTECTION = i32;
pub const OPM_OUTPUT_HARDWARE_PROTECTION_NOT_SUPPORTED: OPM_OUTPUT_HARDWARE_PROTECTION = 0i32;
pub const OPM_OUTPUT_HARDWARE_PROTECTION_SUPPORTED: OPM_OUTPUT_HARDWARE_PROTECTION = 1i32;
#[repr(C, packed(1))]
pub struct OPM_OUTPUT_ID_DATA {
    pub rnRandomNumber: OPM_RANDOM_NUMBER,
    pub ulStatusFlags: u32,
    pub OutputId: u64,
}
impl ::core::marker::Copy for OPM_OUTPUT_ID_DATA {}
impl ::core::clone::Clone for OPM_OUTPUT_ID_DATA {
    fn clone(&self) -> Self {
        *self
    }
}
pub type OPM_PROTECTION_STANDARD_TYPE = u32;
pub const OPM_PROTECTION_STANDARD_OTHER: OPM_PROTECTION_STANDARD_TYPE = 2147483648u32;
pub const OPM_PROTECTION_STANDARD_NONE: OPM_PROTECTION_STANDARD_TYPE = 0u32;
pub const OPM_PROTECTION_STANDARD_IEC61880_525I: OPM_PROTECTION_STANDARD_TYPE = 1u32;
pub const OPM_PROTECTION_STANDARD_IEC61880_2_525I: OPM_PROTECTION_STANDARD_TYPE = 2u32;
pub const OPM_PROTECTION_STANDARD_IEC62375_625P: OPM_PROTECTION_STANDARD_TYPE = 4u32;
pub const OPM_PROTECTION_STANDARD_EIA608B_525: OPM_PROTECTION_STANDARD_TYPE = 8u32;
pub const OPM_PROTECTION_STANDARD_EN300294_625I: OPM_PROTECTION_STANDARD_TYPE = 16u32;
pub const OPM_PROTECTION_STANDARD_CEA805A_TYPEA_525P: OPM_PROTECTION_STANDARD_TYPE = 32u32;
pub const OPM_PROTECTION_STANDARD_CEA805A_TYPEA_750P: OPM_PROTECTION_STANDARD_TYPE = 64u32;
pub const OPM_PROTECTION_STANDARD_CEA805A_TYPEA_1125I: OPM_PROTECTION_STANDARD_TYPE = 128u32;
pub const OPM_PROTECTION_STANDARD_CEA805A_TYPEB_525P: OPM_PROTECTION_STANDARD_TYPE = 256u32;
pub const OPM_PROTECTION_STANDARD_CEA805A_TYPEB_750P: OPM_PROTECTION_STANDARD_TYPE = 512u32;
pub const OPM_PROTECTION_STANDARD_CEA805A_TYPEB_1125I: OPM_PROTECTION_STANDARD_TYPE = 1024u32;
pub const OPM_PROTECTION_STANDARD_ARIBTRB15_525I: OPM_PROTECTION_STANDARD_TYPE = 2048u32;
pub const OPM_PROTECTION_STANDARD_ARIBTRB15_525P: OPM_PROTECTION_STANDARD_TYPE = 4096u32;
pub const OPM_PROTECTION_STANDARD_ARIBTRB15_750P: OPM_PROTECTION_STANDARD_TYPE = 8192u32;
pub const OPM_PROTECTION_STANDARD_ARIBTRB15_1125I: OPM_PROTECTION_STANDARD_TYPE = 16384u32;
pub type OPM_PROTECTION_TYPE = i32;
pub const OPM_PROTECTION_TYPE_OTHER: OPM_PROTECTION_TYPE = -2147483648i32;
pub const OPM_PROTECTION_TYPE_NONE: OPM_PROTECTION_TYPE = 0i32;
pub const OPM_PROTECTION_TYPE_COPP_COMPATIBLE_HDCP: OPM_PROTECTION_TYPE = 1i32;
pub const OPM_PROTECTION_TYPE_ACP: OPM_PROTECTION_TYPE = 2i32;
pub const OPM_PROTECTION_TYPE_CGMSA: OPM_PROTECTION_TYPE = 4i32;
pub const OPM_PROTECTION_TYPE_HDCP: OPM_PROTECTION_TYPE = 8i32;
pub const OPM_PROTECTION_TYPE_DPCP: OPM_PROTECTION_TYPE = 16i32;
pub const OPM_PROTECTION_TYPE_TYPE_ENFORCEMENT_HDCP: OPM_PROTECTION_TYPE = 32i32;
#[repr(C)]
pub struct OPM_RANDOM_NUMBER {
    pub abRandomNumber: [u8; 16],
}
impl ::core::marker::Copy for OPM_RANDOM_NUMBER {}
impl ::core::clone::Clone for OPM_RANDOM_NUMBER {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C, packed(1))]
pub struct OPM_REQUESTED_INFORMATION {
    pub omac: OPM_OMAC,
    pub cbRequestedInformationSize: u32,
    pub abRequestedInformation: [u8; 4076],
}
impl ::core::marker::Copy for OPM_REQUESTED_INFORMATION {}
impl ::core::clone::Clone for OPM_REQUESTED_INFORMATION {
    fn clone(&self) -> Self {
        *self
    }
}
pub const OPM_SET_ACP_AND_CGMSA_SIGNALING: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 161886629, data2: 54916, data3: 19552, data4: [142, 77, 211, 187, 15, 11, 227, 238] };
#[repr(C, packed(1))]
pub struct OPM_SET_ACP_AND_CGMSA_SIGNALING_PARAMETERS {
    pub ulNewTVProtectionStandard: u32,
    pub ulAspectRatioChangeMask1: u32,
    pub ulAspectRatioData1: u32,
    pub ulAspectRatioChangeMask2: u32,
    pub ulAspectRatioData2: u32,
    pub ulAspectRatioChangeMask3: u32,
    pub ulAspectRatioData3: u32,
    pub ulReserved: [u32; 4],
    pub ulReserved2: [u32; 4],
    pub ulReserved3: u32,
}
impl ::core::marker::Copy for OPM_SET_ACP_AND_CGMSA_SIGNALING_PARAMETERS {}
impl ::core::clone::Clone for OPM_SET_ACP_AND_CGMSA_SIGNALING_PARAMETERS {
    fn clone(&self) -> Self {
        *self
    }
}
pub const OPM_SET_HDCP_SRM: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2338256337,
    data2: 49933,
    data3: 17663,
    data4: [132, 165, 234, 113, 220, 231, 143, 19],
};
#[repr(C, packed(1))]
pub struct OPM_SET_HDCP_SRM_PARAMETERS {
    pub ulSRMVersion: u32,
}
impl ::core::marker::Copy for OPM_SET_HDCP_SRM_PARAMETERS {}
impl ::core::clone::Clone for OPM_SET_HDCP_SRM_PARAMETERS {
    fn clone(&self) -> Self {
        *self
    }
}
pub const OPM_SET_PROTECTION_LEVEL: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 2612605564, data2: 20149, data3: 18215, data4: [159, 0, 180, 43, 9, 25, 192, 218] };
pub const OPM_SET_PROTECTION_LEVEL_ACCORDING_TO_CSS_DVD: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 969814846,
    data2: 19648,
    data3: 17582,
    data4: [191, 204, 218, 80, 181, 248, 46, 114],
};
#[repr(C, packed(1))]
pub struct OPM_SET_PROTECTION_LEVEL_PARAMETERS {
    pub ulProtectionType: u32,
    pub ulProtectionLevel: u32,
    pub Reserved: u32,
    pub Reserved2: u32,
}
impl ::core::marker::Copy for OPM_SET_PROTECTION_LEVEL_PARAMETERS {}
impl ::core::clone::Clone for OPM_SET_PROTECTION_LEVEL_PARAMETERS {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C, packed(1))]
pub struct OPM_STANDARD_INFORMATION {
    pub rnRandomNumber: OPM_RANDOM_NUMBER,
    pub ulStatusFlags: u32,
    pub ulInformation: u32,
    pub ulReserved: u32,
    pub ulReserved2: u32,
}
impl ::core::marker::Copy for OPM_STANDARD_INFORMATION {}
impl ::core::clone::Clone for OPM_STANDARD_INFORMATION {
    fn clone(&self) -> Self {
        *self
    }
}
pub type OPM_STATUS = i32;
pub const OPM_STATUS_NORMAL: OPM_STATUS = 0i32;
pub const OPM_STATUS_LINK_LOST: OPM_STATUS = 1i32;
pub const OPM_STATUS_RENEGOTIATION_REQUIRED: OPM_STATUS = 2i32;
pub const OPM_STATUS_TAMPERING_DETECTED: OPM_STATUS = 4i32;
pub const OPM_STATUS_REVOKED_HDCP_DEVICE_ATTACHED: OPM_STATUS = 8i32;
pub type OPM_TYPE = i32;
pub const OPM_OMAC_SIZE: OPM_TYPE = 16i32;
pub const OPM_128_BIT_RANDOM_NUMBER_SIZE: OPM_TYPE = 16i32;
pub const OPM_ENCRYPTED_INITIALIZATION_PARAMETERS_SIZE: OPM_TYPE = 256i32;
pub const OPM_CONFIGURE_SETTING_DATA_SIZE: OPM_TYPE = 4056i32;
pub const OPM_GET_INFORMATION_PARAMETERS_SIZE: OPM_TYPE = 4056i32;
pub const OPM_REQUESTED_INFORMATION_SIZE: OPM_TYPE = 4076i32;
pub const OPM_HDCP_KEY_SELECTION_VECTOR_SIZE: OPM_TYPE = 5i32;
pub const OPM_PROTECTION_TYPE_SIZE: OPM_TYPE = 4i32;
pub const OPM_BUS_TYPE_MASK: OPM_TYPE = 65535i32;
pub const OPM_BUS_IMPLEMENTATION_MODIFIER_MASK: OPM_TYPE = 32767i32;
pub type OPM_TYPE_ENFORCEMENT_HDCP_PROTECTION_LEVEL = i32;
pub const OPM_TYPE_ENFORCEMENT_HDCP_OFF: OPM_TYPE_ENFORCEMENT_HDCP_PROTECTION_LEVEL = 0i32;
pub const OPM_TYPE_ENFORCEMENT_HDCP_ON_WITH_NO_TYPE_RESTRICTION: OPM_TYPE_ENFORCEMENT_HDCP_PROTECTION_LEVEL = 1i32;
pub const OPM_TYPE_ENFORCEMENT_HDCP_ON_WITH_TYPE1_RESTRICTION: OPM_TYPE_ENFORCEMENT_HDCP_PROTECTION_LEVEL = 2i32;
pub const OPM_TYPE_ENFORCEMENT_HDCP_FORCE_ULONG: OPM_TYPE_ENFORCEMENT_HDCP_PROTECTION_LEVEL = 2147483647i32;
pub type OPM_VIDEO_OUTPUT_SEMANTICS = i32;
pub const OPM_VOS_COPP_SEMANTICS: OPM_VIDEO_OUTPUT_SEMANTICS = 0i32;
pub const OPM_VOS_OPM_SEMANTICS: OPM_VIDEO_OUTPUT_SEMANTICS = 1i32;
pub const OPM_VOS_OPM_INDIRECT_DISPLAY: OPM_VIDEO_OUTPUT_SEMANTICS = 2i32;
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub type PDXVAHDSW_CreateDevice = unsafe extern "system" fn(pd3ddevice: super::super::Graphics::Direct3D9::IDirect3DDevice9Ex, phdevice: *mut super::super::Foundation::HANDLE) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_CreateVideoProcessor = unsafe extern "system" fn(hdevice: super::super::Foundation::HANDLE, pvpguid: *const ::windows_sys::core::GUID, phvideoprocessor: *mut super::super::Foundation::HANDLE) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_DestroyDevice = unsafe extern "system" fn(hdevice: super::super::Foundation::HANDLE) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_DestroyVideoProcessor = unsafe extern "system" fn(hvideoprocessor: super::super::Foundation::HANDLE) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_GetVideoProcessBltStatePrivate = unsafe extern "system" fn(hvideoprocessor: super::super::Foundation::HANDLE, pdata: *mut DXVAHD_BLT_STATE_PRIVATE_DATA) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_GetVideoProcessStreamStatePrivate = unsafe extern "system" fn(hvideoprocessor: super::super::Foundation::HANDLE, streamnumber: u32, pdata: *mut DXVAHD_STREAM_STATE_PRIVATE_DATA) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_GetVideoProcessorCaps = unsafe extern "system" fn(hdevice: super::super::Foundation::HANDLE, pcontentdesc: *const DXVAHD_CONTENT_DESC, usage: DXVAHD_DEVICE_USAGE, count: u32, pcaps: *mut DXVAHD_VPCAPS) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_GetVideoProcessorCustomRates = unsafe extern "system" fn(hdevice: super::super::Foundation::HANDLE, pvpguid: *const ::windows_sys::core::GUID, count: u32, prates: *mut DXVAHD_CUSTOM_RATE_DATA) -> ::windows_sys::core::HRESULT;
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub type PDXVAHDSW_GetVideoProcessorDeviceCaps = unsafe extern "system" fn(hdevice: super::super::Foundation::HANDLE, pcontentdesc: *const DXVAHD_CONTENT_DESC, usage: DXVAHD_DEVICE_USAGE, pcaps: *mut DXVAHD_VPDEVCAPS) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_GetVideoProcessorFilterRange = unsafe extern "system" fn(hdevice: super::super::Foundation::HANDLE, filter: DXVAHD_FILTER, prange: *mut DXVAHD_FILTER_RANGE_DATA) -> ::windows_sys::core::HRESULT;
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub type PDXVAHDSW_GetVideoProcessorInputFormats = unsafe extern "system" fn(hdevice: super::super::Foundation::HANDLE, pcontentdesc: *const DXVAHD_CONTENT_DESC, usage: DXVAHD_DEVICE_USAGE, count: u32, pformats: *mut super::super::Graphics::Direct3D9::D3DFORMAT) -> ::windows_sys::core::HRESULT;
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub type PDXVAHDSW_GetVideoProcessorOutputFormats = unsafe extern "system" fn(hdevice: super::super::Foundation::HANDLE, pcontentdesc: *const DXVAHD_CONTENT_DESC, usage: DXVAHD_DEVICE_USAGE, count: u32, pformats: *mut super::super::Graphics::Direct3D9::D3DFORMAT) -> ::windows_sys::core::HRESULT;
pub type PDXVAHDSW_Plugin = unsafe extern "system" fn(size: u32, pcallbacks: *mut ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub type PDXVAHDSW_ProposeVideoPrivateFormat = unsafe extern "system" fn(hdevice: super::super::Foundation::HANDLE, pformat: *mut super::super::Graphics::Direct3D9::D3DFORMAT) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_SetVideoProcessBltState = unsafe extern "system" fn(hvideoprocessor: super::super::Foundation::HANDLE, state: DXVAHD_BLT_STATE, datasize: u32, pdata: *const ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Foundation")]
pub type PDXVAHDSW_SetVideoProcessStreamState = unsafe extern "system" fn(hvideoprocessor: super::super::Foundation::HANDLE, streamnumber: u32, state: DXVAHD_STREAM_STATE, datasize: u32, pdata: *const ::core::ffi::c_void) -> ::windows_sys::core::HRESULT;
#[cfg(all(feature = "Win32_Foundation", feature = "Win32_Graphics_Direct3D9"))]
pub type PDXVAHDSW_VideoProcessBltHD = unsafe extern "system" fn(hvideoprocessor: super::super::Foundation::HANDLE, poutputsurface: super::super::Graphics::Direct3D9::IDirect3DSurface9, outputframe: u32, streamcount: u32, pstreams: *const DXVAHD_STREAM_DATA) -> ::windows_sys::core::HRESULT;
#[cfg(feature = "Win32_Graphics_Direct3D9")]
pub type PDXVAHD_CreateDevice = unsafe extern "system" fn(pd3ddevice: super::super::Graphics::Direct3D9::IDirect3DDevice9Ex, pcontentdesc: *const DXVAHD_CONTENT_DESC, usage: DXVAHD_DEVICE_USAGE, pplugin: ::core::option::Option<PDXVAHDSW_Plugin>, ppdevice: *mut IDXVAHD_Device) -> ::windows_sys::core::HRESULT;
pub type PLAYTO_SOURCE_CREATEFLAGS = i32;
pub const PLAYTO_SOURCE_NONE: PLAYTO_SOURCE_CREATEFLAGS = 0i32;
pub const PLAYTO_SOURCE_IMAGE: PLAYTO_SOURCE_CREATEFLAGS = 1i32;
pub const PLAYTO_SOURCE_AUDIO: PLAYTO_SOURCE_CREATEFLAGS = 2i32;
pub const PLAYTO_SOURCE_VIDEO: PLAYTO_SOURCE_CREATEFLAGS = 4i32;
pub const PLAYTO_SOURCE_PROTECTED: PLAYTO_SOURCE_CREATEFLAGS = 8i32;
pub type PM_CONNECTOR_TYPE = i32;
pub const OPM_CONNECTOR_TYPE_OTHER: PM_CONNECTOR_TYPE = -1i32;
pub const OPM_CONNECTOR_TYPE_VGA: PM_CONNECTOR_TYPE = 0i32;
pub const OPM_CONNECTOR_TYPE_SVIDEO: PM_CONNECTOR_TYPE = 1i32;
pub const OPM_CONNECTOR_TYPE_COMPOSITE_VIDEO: PM_CONNECTOR_TYPE = 2i32;
pub const OPM_CONNECTOR_TYPE_COMPONENT_VIDEO: PM_CONNECTOR_TYPE = 3i32;
pub const OPM_CONNECTOR_TYPE_DVI: PM_CONNECTOR_TYPE = 4i32;
pub const OPM_CONNECTOR_TYPE_HDMI: PM_CONNECTOR_TYPE = 5i32;
pub const OPM_CONNECTOR_TYPE_LVDS: PM_CONNECTOR_TYPE = 6i32;
pub const OPM_CONNECTOR_TYPE_D_JPN: PM_CONNECTOR_TYPE = 8i32;
pub const OPM_CONNECTOR_TYPE_SDI: PM_CONNECTOR_TYPE = 9i32;
pub const OPM_CONNECTOR_TYPE_DISPLAYPORT_EXTERNAL: PM_CONNECTOR_TYPE = 10i32;
pub const OPM_CONNECTOR_TYPE_DISPLAYPORT_EMBEDDED: PM_CONNECTOR_TYPE = 11i32;
pub const OPM_CONNECTOR_TYPE_UDI_EXTERNAL: PM_CONNECTOR_TYPE = 12i32;
pub const OPM_CONNECTOR_TYPE_UDI_EMBEDDED: PM_CONNECTOR_TYPE = 13i32;
pub const OPM_CONNECTOR_TYPE_RESERVED: PM_CONNECTOR_TYPE = 14i32;
pub const OPM_CONNECTOR_TYPE_MIRACAST: PM_CONNECTOR_TYPE = 15i32;
pub const OPM_CONNECTOR_TYPE_TRANSPORT_AGNOSTIC_DIGITAL_MODE_A: PM_CONNECTOR_TYPE = 16i32;
pub const OPM_CONNECTOR_TYPE_TRANSPORT_AGNOSTIC_DIGITAL_MODE_B: PM_CONNECTOR_TYPE = 17i32;
pub const OPM_COPP_COMPATIBLE_CONNECTOR_TYPE_INTERNAL: PM_CONNECTOR_TYPE = -2147483648i32;
pub const PRESENTATION_CURRENT_POSITION: u64 = 9223372036854775807u64;
#[repr(C)]
#[cfg(feature = "Win32_Foundation")]
pub struct ROI_AREA {
    pub rect: super::super::Foundation::RECT,
    pub QPDelta: i32,
}
#[cfg(feature = "Win32_Foundation")]
impl ::core::marker::Copy for ROI_AREA {}
#[cfg(feature = "Win32_Foundation")]
impl ::core::clone::Clone for ROI_AREA {
    fn clone(&self) -> Self {
        *self
    }
}
pub type SAMPLE_PROTECTION_VERSION = i32;
pub const SAMPLE_PROTECTION_VERSION_NO: SAMPLE_PROTECTION_VERSION = 0i32;
pub const SAMPLE_PROTECTION_VERSION_BASIC_LOKI: SAMPLE_PROTECTION_VERSION = 1i32;
pub const SAMPLE_PROTECTION_VERSION_SCATTER: SAMPLE_PROTECTION_VERSION = 2i32;
pub const SAMPLE_PROTECTION_VERSION_RC4: SAMPLE_PROTECTION_VERSION = 3i32;
pub const SAMPLE_PROTECTION_VERSION_AES128CTR: SAMPLE_PROTECTION_VERSION = 4i32;
pub type SEEK_ORIGIN = i32;
pub const _msoBegin: SEEK_ORIGIN = 0i32;
pub const _msoCurrent: SEEK_ORIGIN = 1i32;
#[repr(C)]
pub struct SENSORPROFILEID {
    pub Type: ::windows_sys::core::GUID,
    pub Index: u32,
    pub Unused: u32,
}
impl ::core::marker::Copy for SENSORPROFILEID {}
impl ::core::clone::Clone for SENSORPROFILEID {
    fn clone(&self) -> Self {
        *self
    }
}
pub const SHA_HASH_LEN: u32 = 20u32;
#[repr(C)]
pub struct STREAM_MEDIUM {
    pub gidMedium: ::windows_sys::core::GUID,
    pub unMediumInstance: u32,
}
impl ::core::marker::Copy for STREAM_MEDIUM {}
impl ::core::clone::Clone for STREAM_MEDIUM {
    fn clone(&self) -> Self {
        *self
    }
}
pub const SYSFXUI_DONOTSHOW_BASSBOOST: u32 = 8u32;
pub const SYSFXUI_DONOTSHOW_BASSMANAGEMENT: u32 = 4u32;
pub const SYSFXUI_DONOTSHOW_CHANNELPHANTOMING: u32 = 128u32;
pub const SYSFXUI_DONOTSHOW_HEADPHONEVIRTUALIZATION: u32 = 16u32;
pub const SYSFXUI_DONOTSHOW_LOUDNESSEQUALIZATION: u32 = 1u32;
pub const SYSFXUI_DONOTSHOW_ROOMCORRECTION: u32 = 2u32;
pub const SYSFXUI_DONOTSHOW_SPEAKERFILLING: u32 = 64u32;
pub const SYSFXUI_DONOTSHOW_VIRTUALSURROUND: u32 = 32u32;
#[repr(C)]
pub struct TOC_DESCRIPTOR {
    pub guidID: ::windows_sys::core::GUID,
    pub wStreamNumber: u16,
    pub guidType: ::windows_sys::core::GUID,
    pub wLanguageIndex: u16,
}
impl ::core::marker::Copy for TOC_DESCRIPTOR {}
impl ::core::clone::Clone for TOC_DESCRIPTOR {
    fn clone(&self) -> Self {
        *self
    }
}
#[repr(C)]
pub struct TOC_ENTRY_DESCRIPTOR {
    pub qwStartTime: u64,
    pub qwEndTime: u64,
    pub qwStartPacketOffset: u64,
    pub qwEndPacketOffset: u64,
    pub qwRepresentativeFrameTime: u64,
}
impl ::core::marker::Copy for TOC_ENTRY_DESCRIPTOR {}
impl ::core::clone::Clone for TOC_ENTRY_DESCRIPTOR {
    fn clone(&self) -> Self {
        *self
    }
}
pub const TOC_ENTRY_MAX_TITLE_SIZE: u32 = 65535u32;
pub const TOC_MAX_DESCRIPTION_SIZE: u32 = 65535u32;
pub type TOC_POS_TYPE = i32;
pub const TOC_POS_INHEADER: TOC_POS_TYPE = 0i32;
pub const TOC_POS_TOPLEVELOBJECT: TOC_POS_TYPE = 1i32;
pub const VIDEO_ZOOM_RECT: ::windows_sys::core::GUID = ::windows_sys::core::GUID {
    data1: 2057967160,
    data2: 7039,
    data3: 19603,
    data4: [189, 137, 91, 156, 159, 182, 252, 240],
};
pub const VorbisDecoderMFT: ::windows_sys::core::GUID = ::windows_sys::core::GUID { data1: 437882610, data2: 24805, data3: 20136, data4: [144, 216, 218, 31, 40, 50, 194, 136] };
pub const WMAAECMA_E_NO_ACTIVE_RENDER_STREAM: u32 = 2278293514u32;
pub type WMT_PROP_DATATYPE = i32;
pub const WMT_PROP_TYPE_DWORD: WMT_PROP_DATATYPE = 0i32;
pub const WMT_PROP_TYPE_STRING: WMT_PROP_DATATYPE = 1i32;
pub const WMT_PROP_TYPE_BINARY: WMT_PROP_DATATYPE = 2i32;
pub const WMT_PROP_TYPE_BOOL: WMT_PROP_DATATYPE = 3i32;
pub const WMT_PROP_TYPE_QWORD: WMT_PROP_DATATYPE = 4i32;
pub const WMT_PROP_TYPE_WORD: WMT_PROP_DATATYPE = 5i32;
pub const WMT_PROP_TYPE_GUID: WMT_PROP_DATATYPE = 6i32;
pub type WMV_DYNAMIC_FLAGS = i32;
pub const WMV_DYNAMIC_BITRATE: WMV_DYNAMIC_FLAGS = 1i32;
pub const WMV_DYNAMIC_RESOLUTION: WMV_DYNAMIC_FLAGS = 2i32;
pub const WMV_DYNAMIC_COMPLEXITY: WMV_DYNAMIC_FLAGS = 4i32;
pub const WM_CODEC_ONEPASS_CBR: u32 = 1u32;
pub const WM_CODEC_ONEPASS_VBR: u32 = 2u32;
pub const WM_CODEC_TWOPASS_CBR: u32 = 4u32;
pub const WM_CODEC_TWOPASS_VBR_PEAKCONSTRAINED: u32 = 16u32;
pub const WM_CODEC_TWOPASS_VBR_UNCONSTRAINED: u32 = 8u32;
pub type _MFP_CREDENTIAL_FLAGS = i32;
pub const MFP_CREDENTIAL_PROMPT: _MFP_CREDENTIAL_FLAGS = 1i32;
pub const MFP_CREDENTIAL_SAVE: _MFP_CREDENTIAL_FLAGS = 2i32;
pub const MFP_CREDENTIAL_DO_NOT_CACHE: _MFP_CREDENTIAL_FLAGS = 4i32;
pub const MFP_CREDENTIAL_CLEAR_TEXT: _MFP_CREDENTIAL_FLAGS = 8i32;
pub const MFP_CREDENTIAL_PROXY: _MFP_CREDENTIAL_FLAGS = 16i32;
pub const MFP_CREDENTIAL_LOGGED_ON_USER: _MFP_CREDENTIAL_FLAGS = 32i32;
pub type _MFP_MEDIAITEM_CHARACTERISTICS = i32;
pub const MFP_MEDIAITEM_IS_LIVE: _MFP_MEDIAITEM_CHARACTERISTICS = 1i32;
pub const MFP_MEDIAITEM_CAN_SEEK: _MFP_MEDIAITEM_CHARACTERISTICS = 2i32;
pub const MFP_MEDIAITEM_CAN_PAUSE: _MFP_MEDIAITEM_CHARACTERISTICS = 4i32;
pub const MFP_MEDIAITEM_HAS_SLOW_SEEK: _MFP_MEDIAITEM_CHARACTERISTICS = 8i32;
pub type _MFT_ENUM_FLAG = i32;
pub const MFT_ENUM_FLAG_SYNCMFT: _MFT_ENUM_FLAG = 1i32;
pub const MFT_ENUM_FLAG_ASYNCMFT: _MFT_ENUM_FLAG = 2i32;
pub const MFT_ENUM_FLAG_HARDWARE: _MFT_ENUM_FLAG = 4i32;
pub const MFT_ENUM_FLAG_FIELDOFUSE: _MFT_ENUM_FLAG = 8i32;
pub const MFT_ENUM_FLAG_LOCALMFT: _MFT_ENUM_FLAG = 16i32;
pub const MFT_ENUM_FLAG_TRANSCODE_ONLY: _MFT_ENUM_FLAG = 32i32;
pub const MFT_ENUM_FLAG_SORTANDFILTER: _MFT_ENUM_FLAG = 64i32;
pub const MFT_ENUM_FLAG_SORTANDFILTER_APPROVED_ONLY: _MFT_ENUM_FLAG = 192i32;
pub const MFT_ENUM_FLAG_SORTANDFILTER_WEB_ONLY: _MFT_ENUM_FLAG = 320i32;
pub const MFT_ENUM_FLAG_SORTANDFILTER_WEB_ONLY_EDGEMODE: _MFT_ENUM_FLAG = 576i32;
pub const MFT_ENUM_FLAG_UNTRUSTED_STOREMFT: _MFT_ENUM_FLAG = 1024i32;
pub const MFT_ENUM_FLAG_ALL: _MFT_ENUM_FLAG = 63i32;
pub type _MFT_INPUT_DATA_BUFFER_FLAGS = i32;
pub const MFT_INPUT_DATA_BUFFER_PLACEHOLDER: _MFT_INPUT_DATA_BUFFER_FLAGS = -1i32;
pub type _MFT_INPUT_STATUS_FLAGS = i32;
pub const MFT_INPUT_STATUS_ACCEPT_DATA: _MFT_INPUT_STATUS_FLAGS = 1i32;
pub type _MFT_INPUT_STREAM_INFO_FLAGS = i32;
pub const MFT_INPUT_STREAM_WHOLE_SAMPLES: _MFT_INPUT_STREAM_INFO_FLAGS = 1i32;
pub const MFT_INPUT_STREAM_SINGLE_SAMPLE_PER_BUFFER: _MFT_INPUT_STREAM_INFO_FLAGS = 2i32;
pub const MFT_INPUT_STREAM_FIXED_SAMPLE_SIZE: _MFT_INPUT_STREAM_INFO_FLAGS = 4i32;
pub const MFT_INPUT_STREAM_HOLDS_BUFFERS: _MFT_INPUT_STREAM_INFO_FLAGS = 8i32;
pub const MFT_INPUT_STREAM_DOES_NOT_ADDREF: _MFT_INPUT_STREAM_INFO_FLAGS = 256i32;
pub const MFT_INPUT_STREAM_REMOVABLE: _MFT_INPUT_STREAM_INFO_FLAGS = 512i32;
pub const MFT_INPUT_STREAM_OPTIONAL: _MFT_INPUT_STREAM_INFO_FLAGS = 1024i32;
pub const MFT_INPUT_STREAM_PROCESSES_IN_PLACE: _MFT_INPUT_STREAM_INFO_FLAGS = 2048i32;
pub type _MFT_OUTPUT_DATA_BUFFER_FLAGS = i32;
pub const MFT_OUTPUT_DATA_BUFFER_INCOMPLETE: _MFT_OUTPUT_DATA_BUFFER_FLAGS = 16777216i32;
pub const MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE: _MFT_OUTPUT_DATA_BUFFER_FLAGS = 256i32;
pub const MFT_OUTPUT_DATA_BUFFER_STREAM_END: _MFT_OUTPUT_DATA_BUFFER_FLAGS = 512i32;
pub const MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE: _MFT_OUTPUT_DATA_BUFFER_FLAGS = 768i32;
pub type _MFT_OUTPUT_STATUS_FLAGS = i32;
pub const MFT_OUTPUT_STATUS_SAMPLE_READY: _MFT_OUTPUT_STATUS_FLAGS = 1i32;
pub type _MFT_OUTPUT_STREAM_INFO_FLAGS = i32;
pub const MFT_OUTPUT_STREAM_WHOLE_SAMPLES: _MFT_OUTPUT_STREAM_INFO_FLAGS = 1i32;
pub const MFT_OUTPUT_STREAM_SINGLE_SAMPLE_PER_BUFFER: _MFT_OUTPUT_STREAM_INFO_FLAGS = 2i32;
pub const MFT_OUTPUT_STREAM_FIXED_SAMPLE_SIZE: _MFT_OUTPUT_STREAM_INFO_FLAGS = 4i32;
pub const MFT_OUTPUT_STREAM_DISCARDABLE: _MFT_OUTPUT_STREAM_INFO_FLAGS = 8i32;
pub const MFT_OUTPUT_STREAM_OPTIONAL: _MFT_OUTPUT_STREAM_INFO_FLAGS = 16i32;
pub const MFT_OUTPUT_STREAM_PROVIDES_SAMPLES: _MFT_OUTPUT_STREAM_INFO_FLAGS = 256i32;
pub const MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES: _MFT_OUTPUT_STREAM_INFO_FLAGS = 512i32;
pub const MFT_OUTPUT_STREAM_LAZY_READ: _MFT_OUTPUT_STREAM_INFO_FLAGS = 1024i32;
pub const MFT_OUTPUT_STREAM_REMOVABLE: _MFT_OUTPUT_STREAM_INFO_FLAGS = 2048i32;
pub type _MFT_PROCESS_OUTPUT_FLAGS = i32;
pub const MFT_PROCESS_OUTPUT_DISCARD_WHEN_NO_BUFFER: _MFT_PROCESS_OUTPUT_FLAGS = 1i32;
pub const MFT_PROCESS_OUTPUT_REGENERATE_LAST_OUTPUT: _MFT_PROCESS_OUTPUT_FLAGS = 2i32;
pub type _MFT_PROCESS_OUTPUT_STATUS = i32;
pub const MFT_PROCESS_OUTPUT_STATUS_NEW_STREAMS: _MFT_PROCESS_OUTPUT_STATUS = 256i32;
pub type _MFT_SET_TYPE_FLAGS = i32;
pub const MFT_SET_TYPE_TEST_ONLY: _MFT_SET_TYPE_FLAGS = 1i32;
pub type __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0001 = i32;
pub const MFVirtualCameraType_SoftwareCameraSource: __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0001 = 0i32;
pub type __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0002 = i32;
pub const MFVirtualCameraLifetime_Session: __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0002 = 0i32;
pub const MFVirtualCameraLifetime_System: __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0002 = 1i32;
pub type __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0003 = i32;
pub const MFVirtualCameraAccess_CurrentUser: __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0003 = 0i32;
pub const MFVirtualCameraAccess_AllUsers: __MIDL___MIDL_itf_mfvirtualcamera_0000_0000_0003 = 1i32;
pub type eAVAudioChannelConfig = i32;
pub const eAVAudioChannelConfig_FRONT_LEFT: eAVAudioChannelConfig = 1i32;
pub const eAVAudioChannelConfig_FRONT_RIGHT: eAVAudioChannelConfig = 2i32;
pub const eAVAudioChannelConfig_FRONT_CENTER: eAVAudioChannelConfig = 4i32;
pub const eAVAudioChannelConfig_LOW_FREQUENCY: eAVAudioChannelConfig = 8i32;
pub const eAVAudioChannelConfig_BACK_LEFT: eAVAudioChannelConfig = 16i32;
pub const eAVAudioChannelConfig_BACK_RIGHT: eAVAudioChannelConfig = 32i32;
pub const eAVAudioChannelConfig_FRONT_LEFT_OF_CENTER: eAVAudioChannelConfig = 64i32;
pub const eAVAudioChannelConfig_FRONT_RIGHT_OF_CENTER: eAVAudioChannelConfig = 128i32;
pub const eAVAudioChannelConfig_BACK_CENTER: eAVAudioChannelConfig = 256i32;
pub const eAVAudioChannelConfig_SIDE_LEFT: eAVAudioChannelConfig = 512i32;
pub const eAVAudioChannelConfig_SIDE_RIGHT: eAVAudioChannelConfig = 1024i32;
pub const eAVAudioChannelConfig_TOP_CENTER: eAVAudioChannelConfig = 2048i32;
pub const eAVAudioChannelConfig_TOP_FRONT_LEFT: eAVAudioChannelConfig = 4096i32;
pub const eAVAudioChannelConfig_TOP_FRONT_CENTER: eAVAudioChannelConfig = 8192i32;
pub const eAVAudioChannelConfig_TOP_FRONT_RIGHT: eAVAudioChannelConfig = 16384i32;
pub const eAVAudioChannelConfig_TOP_BACK_LEFT: eAVAudioChannelConfig = 32768i32;
pub const eAVAudioChannelConfig_TOP_BACK_CENTER: eAVAudioChannelConfig = 65536i32;
pub const eAVAudioChannelConfig_TOP_BACK_RIGHT: eAVAudioChannelConfig = 131072i32;
pub type eAVDDSurroundMode = i32;
pub const eAVDDSurroundMode_NotIndicated: eAVDDSurroundMode = 0i32;
pub const eAVDDSurroundMode_No: eAVDDSurroundMode = 1i32;
pub const eAVDDSurroundMode_Yes: eAVDDSurroundMode = 2i32;
pub type eAVDSPLoudnessEqualization = i32;
pub const eAVDSPLoudnessEqualization_OFF: eAVDSPLoudnessEqualization = 0i32;
pub const eAVDSPLoudnessEqualization_ON: eAVDSPLoudnessEqualization = 1i32;
pub const eAVDSPLoudnessEqualization_AUTO: eAVDSPLoudnessEqualization = 2i32;
pub type eAVDSPSpeakerFill = i32;
pub const eAVDSPSpeakerFill_OFF: eAVDSPSpeakerFill = 0i32;
pub const eAVDSPSpeakerFill_ON: eAVDSPSpeakerFill = 1i32;
pub const eAVDSPSpeakerFill_AUTO: eAVDSPSpeakerFill = 2i32;
pub type eAVDecAACDownmixMode = i32;
pub const eAVDecAACUseISODownmix: eAVDecAACDownmixMode = 0i32;
pub const eAVDecAACUseARIBDownmix: eAVDecAACDownmixMode = 1i32;
pub type eAVDecAudioDualMono = i32;
pub const eAVDecAudioDualMono_IsNotDualMono: eAVDecAudioDualMono = 0i32;
pub const eAVDecAudioDualMono_IsDualMono: eAVDecAudioDualMono = 1i32;
pub const eAVDecAudioDualMono_UnSpecified: eAVDecAudioDualMono = 2i32;
pub type eAVDecAudioDualMonoReproMode = i32;
pub const eAVDecAudioDualMonoReproMode_STEREO: eAVDecAudioDualMonoReproMode = 0i32;
pub const eAVDecAudioDualMonoReproMode_LEFT_MONO: eAVDecAudioDualMonoReproMode = 1i32;
pub const eAVDecAudioDualMonoReproMode_RIGHT_MONO: eAVDecAudioDualMonoReproMode = 2i32;
pub const eAVDecAudioDualMonoReproMode_MIX_MONO: eAVDecAudioDualMonoReproMode = 3i32;
pub type eAVDecDDMatrixDecodingMode = i32;
pub const eAVDecDDMatrixDecodingMode_OFF: eAVDecDDMatrixDecodingMode = 0i32;
pub const eAVDecDDMatrixDecodingMode_ON: eAVDecDDMatrixDecodingMode = 1i32;
pub const eAVDecDDMatrixDecodingMode_AUTO: eAVDecDDMatrixDecodingMode = 2i32;
pub type eAVDecDDOperationalMode = i32;
pub const eAVDecDDOperationalMode_NONE: eAVDecDDOperationalMode = 0i32;
pub const eAVDecDDOperationalMode_LINE: eAVDecDDOperationalMode = 1i32;
pub const eAVDecDDOperationalMode_RF: eAVDecDDOperationalMode = 2i32;
pub const eAVDecDDOperationalMode_CUSTOM0: eAVDecDDOperationalMode = 3i32;
pub const eAVDecDDOperationalMode_CUSTOM1: eAVDecDDOperationalMode = 4i32;
pub const eAVDecDDOperationalMode_PORTABLE8: eAVDecDDOperationalMode = 5i32;
pub const eAVDecDDOperationalMode_PORTABLE11: eAVDecDDOperationalMode = 6i32;
pub const eAVDecDDOperationalMode_PORTABLE14: eAVDecDDOperationalMode = 7i32;
pub type eAVDecDDStereoDownMixMode = i32;
pub const eAVDecDDStereoDownMixMode_Auto: eAVDecDDStereoDownMixMode = 0i32;
pub const eAVDecDDStereoDownMixMode_LtRt: eAVDecDDStereoDownMixMode = 1i32;
pub const eAVDecDDStereoDownMixMode_LoRo: eAVDecDDStereoDownMixMode = 2i32;
pub type eAVDecHEAACDynamicRangeControl = i32;
pub const eAVDecHEAACDynamicRangeControl_OFF: eAVDecHEAACDynamicRangeControl = 0i32;
pub const eAVDecHEAACDynamicRangeControl_ON: eAVDecHEAACDynamicRangeControl = 1i32;
pub type eAVDecVideoCodecType = i32;
pub const eAVDecVideoCodecType_NOTPLAYING: eAVDecVideoCodecType = 0i32;
pub const eAVDecVideoCodecType_MPEG2: eAVDecVideoCodecType = 1i32;
pub const eAVDecVideoCodecType_H264: eAVDecVideoCodecType = 2i32;
pub type eAVDecVideoDXVABusEncryption = i32;
pub const eAVDecVideoDXVABusEncryption_NONE: eAVDecVideoDXVABusEncryption = 0i32;
pub const eAVDecVideoDXVABusEncryption_PRIVATE: eAVDecVideoDXVABusEncryption = 1i32;
pub const eAVDecVideoDXVABusEncryption_AES: eAVDecVideoDXVABusEncryption = 2i32;
pub type eAVDecVideoDXVAMode = i32;
pub const eAVDecVideoDXVAMode_NOTPLAYING: eAVDecVideoDXVAMode = 0i32;
pub const eAVDecVideoDXVAMode_SW: eAVDecVideoDXVAMode = 1i32;
pub const eAVDecVideoDXVAMode_MC: eAVDecVideoDXVAMode = 2i32;
pub const eAVDecVideoDXVAMode_IDCT: eAVDecVideoDXVAMode = 3i32;
pub const eAVDecVideoDXVAMode_VLD: eAVDecVideoDXVAMode = 4i32;
pub type eAVDecVideoH264ErrorConcealment = i32;
pub const eErrorConcealmentTypeDrop: eAVDecVideoH264ErrorConcealment = 0i32;
pub const eErrorConcealmentTypeBasic: eAVDecVideoH264ErrorConcealment = 1i32;
pub const eErrorConcealmentTypeAdvanced: eAVDecVideoH264ErrorConcealment = 2i32;
pub const eErrorConcealmentTypeDXVASetBlack: eAVDecVideoH264ErrorConcealment = 3i32;
pub type eAVDecVideoInputScanType = i32;
pub const eAVDecVideoInputScan_Unknown: eAVDecVideoInputScanType = 0i32;
pub const eAVDecVideoInputScan_Progressive: eAVDecVideoInputScanType = 1i32;
pub const eAVDecVideoInputScan_Interlaced_UpperFieldFirst: eAVDecVideoInputScanType = 2i32;
pub const eAVDecVideoInputScan_Interlaced_LowerFieldFirst: eAVDecVideoInputScanType = 3i32;
pub type eAVDecVideoMPEG2ErrorConcealment = i32;
pub const eErrorConcealmentOff: eAVDecVideoMPEG2ErrorConcealment = 0i32;
pub const eErrorConcealmentOn: eAVDecVideoMPEG2ErrorConcealment = 1i32;
pub type eAVDecVideoSWPowerLevel = i32;
pub const eAVDecVideoSWPowerLevel_BatteryLife: eAVDecVideoSWPowerLevel = 0i32;
pub const eAVDecVideoSWPowerLevel_Balanced: eAVDecVideoSWPowerLevel = 50i32;
pub const eAVDecVideoSWPowerLevel_VideoQuality: eAVDecVideoSWPowerLevel = 100i32;
pub type eAVDecVideoSoftwareDeinterlaceMode = i32;
pub const eAVDecVideoSoftwareDeinterlaceMode_NoDeinterlacing: eAVDecVideoSoftwareDeinterlaceMode = 0i32;
pub const eAVDecVideoSoftwareDeinterlaceMode_ProgressiveDeinterlacing: eAVDecVideoSoftwareDeinterlaceMode = 1i32;
pub const eAVDecVideoSoftwareDeinterlaceMode_BOBDeinterlacing: eAVDecVideoSoftwareDeinterlaceMode = 2i32;
pub const eAVDecVideoSoftwareDeinterlaceMode_SmartBOBDeinterlacing: eAVDecVideoSoftwareDeinterlaceMode = 3i32;
pub type eAVEncAdaptiveMode = i32;
pub const eAVEncAdaptiveMode_None: eAVEncAdaptiveMode = 0i32;
pub const eAVEncAdaptiveMode_Resolution: eAVEncAdaptiveMode = 1i32;
pub const eAVEncAdaptiveMode_FrameRate: eAVEncAdaptiveMode = 2i32;
pub type eAVEncAudioDualMono = i32;
pub const eAVEncAudioDualMono_SameAsInput: eAVEncAudioDualMono = 0i32;
pub const eAVEncAudioDualMono_Off: eAVEncAudioDualMono = 1i32;
pub const eAVEncAudioDualMono_On: eAVEncAudioDualMono = 2i32;
pub type eAVEncAudioInputContent = i32;
pub const AVEncAudioInputContent_Unknown: eAVEncAudioInputContent = 0i32;
pub const AVEncAudioInputContent_Voice: eAVEncAudioInputContent = 1i32;
pub const AVEncAudioInputContent_Music: eAVEncAudioInputContent = 2i32;
pub type eAVEncChromaEncodeMode = i32;
pub const eAVEncChromaEncodeMode_420: eAVEncChromaEncodeMode = 0i32;
pub const eAVEncChromaEncodeMode_444: eAVEncChromaEncodeMode = 1i32;
pub const eAVEncChromaEncodeMode_444_v2: eAVEncChromaEncodeMode = 2i32;
pub type eAVEncCommonRateControlMode = i32;
pub const eAVEncCommonRateControlMode_CBR: eAVEncCommonRateControlMode = 0i32;
pub const eAVEncCommonRateControlMode_PeakConstrainedVBR: eAVEncCommonRateControlMode = 1i32;
pub const eAVEncCommonRateControlMode_UnconstrainedVBR: eAVEncCommonRateControlMode = 2i32;
pub const eAVEncCommonRateControlMode_Quality: eAVEncCommonRateControlMode = 3i32;
pub const eAVEncCommonRateControlMode_LowDelayVBR: eAVEncCommonRateControlMode = 4i32;
pub const eAVEncCommonRateControlMode_GlobalVBR: eAVEncCommonRateControlMode = 5i32;
pub const eAVEncCommonRateControlMode_GlobalLowDelayVBR: eAVEncCommonRateControlMode = 6i32;
pub type eAVEncCommonStreamEndHandling = i32;
pub const eAVEncCommonStreamEndHandling_DiscardPartial: eAVEncCommonStreamEndHandling = 0i32;
pub const eAVEncCommonStreamEndHandling_EnsureComplete: eAVEncCommonStreamEndHandling = 1i32;
pub type eAVEncDDAtoDConverterType = i32;
pub const eAVEncDDAtoDConverterType_Standard: eAVEncDDAtoDConverterType = 0i32;
pub const eAVEncDDAtoDConverterType_HDCD: eAVEncDDAtoDConverterType = 1i32;
pub type eAVEncDDDynamicRangeCompressionControl = i32;
pub const eAVEncDDDynamicRangeCompressionControl_None: eAVEncDDDynamicRangeCompressionControl = 0i32;
pub const eAVEncDDDynamicRangeCompressionControl_FilmStandard: eAVEncDDDynamicRangeCompressionControl = 1i32;
pub const eAVEncDDDynamicRangeCompressionControl_FilmLight: eAVEncDDDynamicRangeCompressionControl = 2i32;
pub const eAVEncDDDynamicRangeCompressionControl_MusicStandard: eAVEncDDDynamicRangeCompressionControl = 3i32;
pub const eAVEncDDDynamicRangeCompressionControl_MusicLight: eAVEncDDDynamicRangeCompressionControl = 4i32;
pub const eAVEncDDDynamicRangeCompressionControl_Speech: eAVEncDDDynamicRangeCompressionControl = 5i32;
pub type eAVEncDDHeadphoneMode = i32;
pub const eAVEncDDHeadphoneMode_NotIndicated: eAVEncDDHeadphoneMode = 0i32;
pub const eAVEncDDHeadphoneMode_NotEncoded: eAVEncDDHeadphoneMode = 1i32;
pub const eAVEncDDHeadphoneMode_Encoded: eAVEncDDHeadphoneMode = 2i32;
pub type eAVEncDDPreferredStereoDownMixMode = i32;
pub const eAVEncDDPreferredStereoDownMixMode_LtRt: eAVEncDDPreferredStereoDownMixMode = 0i32;
pub const eAVEncDDPreferredStereoDownMixMode_LoRo: eAVEncDDPreferredStereoDownMixMode = 1i32;
pub type eAVEncDDProductionRoomType = i32;
pub const eAVEncDDProductionRoomType_NotIndicated: eAVEncDDProductionRoomType = 0i32;
pub const eAVEncDDProductionRoomType_Large: eAVEncDDProductionRoomType = 1i32;
pub const eAVEncDDProductionRoomType_Small: eAVEncDDProductionRoomType = 2i32;
pub type eAVEncDDService = i32;
pub const eAVEncDDService_CM: eAVEncDDService = 0i32;
pub const eAVEncDDService_ME: eAVEncDDService = 1i32;
pub const eAVEncDDService_VI: eAVEncDDService = 2i32;
pub const eAVEncDDService_HI: eAVEncDDService = 3i32;
pub const eAVEncDDService_D: eAVEncDDService = 4i32;
pub const eAVEncDDService_C: eAVEncDDService = 5i32;
pub const eAVEncDDService_E: eAVEncDDService = 6i32;
pub const eAVEncDDService_VO: eAVEncDDService = 7i32;
pub type eAVEncDDSurroundExMode = i32;
pub const eAVEncDDSurroundExMode_NotIndicated: eAVEncDDSurroundExMode = 0i32;
pub const eAVEncDDSurroundExMode_No: eAVEncDDSurroundExMode = 1i32;
pub const eAVEncDDSurroundExMode_Yes: eAVEncDDSurroundExMode = 2i32;
pub type eAVEncH263PictureType = i32;
pub const eAVEncH263PictureType_I: eAVEncH263PictureType = 0i32;
pub const eAVEncH263PictureType_P: eAVEncH263PictureType = 1i32;
pub const eAVEncH263PictureType_B: eAVEncH263PictureType = 2i32;
pub type eAVEncH263VLevel = i32;
pub const eAVEncH263VLevel1: eAVEncH263VLevel = 10i32;
pub const eAVEncH263VLevel2: eAVEncH263VLevel = 20i32;
pub const eAVEncH263VLevel3: eAVEncH263VLevel = 30i32;
pub const eAVEncH263VLevel4: eAVEncH263VLevel = 40i32;
pub const eAVEncH263VLevel4_5: eAVEncH263VLevel = 45i32;
pub const eAVEncH263VLevel5: eAVEncH263VLevel = 50i32;
pub const eAVEncH263VLevel6: eAVEncH263VLevel = 60i32;
pub const eAVEncH263VLevel7: eAVEncH263VLevel = 70i32;
pub type eAVEncH263VProfile = i32;
pub const eAVEncH263VProfile_Base: eAVEncH263VProfile = 0i32;
pub const eAVEncH263VProfile_CompatibilityV2: eAVEncH263VProfile = 1i32;
pub const eAVEncH263VProfile_CompatibilityV1: eAVEncH263VProfile = 2i32;
pub const eAVEncH263VProfile_WirelessV2: eAVEncH263VProfile = 3i32;
pub const eAVEncH263VProfile_WirelessV3: eAVEncH263VProfile = 4i32;
pub const eAVEncH263VProfile_HighCompression: eAVEncH263VProfile = 5i32;
pub const eAVEncH263VProfile_Internet: eAVEncH263VProfile = 6i32;
pub const eAVEncH263VProfile_Interlace: eAVEncH263VProfile = 7i32;
pub const eAVEncH263VProfile_HighLatency: eAVEncH263VProfile = 8i32;
pub type eAVEncH264PictureType = i32;
pub const eAVEncH264PictureType_IDR: eAVEncH264PictureType = 0i32;
pub const eAVEncH264PictureType_P: eAVEncH264PictureType = 1i32;
pub const eAVEncH264PictureType_B: eAVEncH264PictureType = 2i32;
pub type eAVEncH264VLevel = i32;
pub const eAVEncH264VLevel1: eAVEncH264VLevel = 10i32;
pub const eAVEncH264VLevel1_b: eAVEncH264VLevel = 11i32;
pub const eAVEncH264VLevel1_1: eAVEncH264VLevel = 11i32;
pub const eAVEncH264VLevel1_2: eAVEncH264VLevel = 12i32;
pub const eAVEncH264VLevel1_3: eAVEncH264VLevel = 13i32;
pub const eAVEncH264VLevel2: eAVEncH264VLevel = 20i32;
pub const eAVEncH264VLevel2_1: eAVEncH264VLevel = 21i32;
pub const eAVEncH264VLevel2_2: eAVEncH264VLevel = 22i32;
pub const eAVEncH264VLevel3: eAVEncH264VLevel = 30i32;
pub const eAVEncH264VLevel3_1: eAVEncH264VLevel = 31i32;
pub const eAVEncH264VLevel3_2: eAVEncH264VLevel = 32i32;
pub const eAVEncH264VLevel4: eAVEncH264VLevel = 40i32;
pub const eAVEncH264VLevel4_1: eAVEncH264VLevel = 41i32;
pub const eAVEncH264VLevel4_2: eAVEncH264VLevel = 42i32;
pub const eAVEncH264VLevel5: eAVEncH264VLevel = 50i32;
pub const eAVEncH264VLevel5_1: eAVEncH264VLevel = 51i32;
pub const eAVEncH264VLevel5_2: eAVEncH264VLevel = 52i32;
pub type eAVEncH264VProfile = i32;
pub const eAVEncH264VProfile_unknown: eAVEncH264VProfile = 0i32;
pub const eAVEncH264VProfile_Simple: eAVEncH264VProfile = 66i32;
pub const eAVEncH264VProfile_Base: eAVEncH264VProfile = 66i32;
pub const eAVEncH264VProfile_Main: eAVEncH264VProfile = 77i32;
pub const eAVEncH264VProfile_High: eAVEncH264VProfile = 100i32;
pub const eAVEncH264VProfile_422: eAVEncH264VProfile = 122i32;
pub const eAVEncH264VProfile_High10: eAVEncH264VProfile = 110i32;
pub const eAVEncH264VProfile_444: eAVEncH264VProfile = 244i32;
pub const eAVEncH264VProfile_Extended: eAVEncH264VProfile = 88i32;
pub const eAVEncH264VProfile_ScalableBase: eAVEncH264VProfile = 83i32;
pub const eAVEncH264VProfile_ScalableHigh: eAVEncH264VProfile = 86i32;
pub const eAVEncH264VProfile_MultiviewHigh: eAVEncH264VProfile = 118i32;
pub const eAVEncH264VProfile_StereoHigh: eAVEncH264VProfile = 128i32;
pub const eAVEncH264VProfile_ConstrainedBase: eAVEncH264VProfile = 256i32;
pub const eAVEncH264VProfile_UCConstrainedHigh: eAVEncH264VProfile = 257i32;
pub const eAVEncH264VProfile_UCScalableConstrainedBase: eAVEncH264VProfile = 258i32;
pub const eAVEncH264VProfile_UCScalableConstrainedHigh: eAVEncH264VProfile = 259i32;
pub type eAVEncH265VLevel = i32;
pub const eAVEncH265VLevel1: eAVEncH265VLevel = 30i32;
pub const eAVEncH265VLevel2: eAVEncH265VLevel = 60i32;
pub const eAVEncH265VLevel2_1: eAVEncH265VLevel = 63i32;
pub const eAVEncH265VLevel3: eAVEncH265VLevel = 90i32;
pub const eAVEncH265VLevel3_1: eAVEncH265VLevel = 93i32;
pub const eAVEncH265VLevel4: eAVEncH265VLevel = 120i32;
pub const eAVEncH265VLevel4_1: eAVEncH265VLevel = 123i32;
pub const eAVEncH265VLevel5: eAVEncH265VLevel = 150i32;
pub const eAVEncH265VLevel5_1: eAVEncH265VLevel = 153i32;
pub const eAVEncH265VLevel5_2: eAVEncH265VLevel = 156i32;
pub const eAVEncH265VLevel6: eAVEncH265VLevel = 180i32;
pub const eAVEncH265VLevel6_1: eAVEncH265VLevel = 183i32;
pub const eAVEncH265VLevel6_2: eAVEncH265VLevel = 186i32;
pub type eAVEncH265VProfile = i32;
pub const eAVEncH265VProfile_unknown: eAVEncH265VProfile = 0i32;
pub const eAVEncH265VProfile_Main_420_8: eAVEncH265VProfile = 1i32;
pub const eAVEncH265VProfile_Main_420_10: eAVEncH265VProfile = 2i32;
pub const eAVEncH265VProfile_Main_420_12: eAVEncH265VProfile = 3i32;
pub const eAVEncH265VProfile_Main_422_10: eAVEncH265VProfile = 4i32;
pub const eAVEncH265VProfile_Main_422_12: eAVEncH265VProfile = 5i32;
pub const eAVEncH265VProfile_Main_444_8: eAVEncH265VProfile = 6i32;
pub const eAVEncH265VProfile_Main_444_10: eAVEncH265VProfile = 7i32;
pub const eAVEncH265VProfile_Main_444_12: eAVEncH265VProfile = 8i32;
pub const eAVEncH265VProfile_Monochrome_12: eAVEncH265VProfile = 9i32;
pub const eAVEncH265VProfile_Monochrome_16: eAVEncH265VProfile = 10i32;
pub const eAVEncH265VProfile_MainIntra_420_8: eAVEncH265VProfile = 11i32;
pub const eAVEncH265VProfile_MainIntra_420_10: eAVEncH265VProfile = 12i32;
pub const eAVEncH265VProfile_MainIntra_420_12: eAVEncH265VProfile = 13i32;
pub const eAVEncH265VProfile_MainIntra_422_10: eAVEncH265VProfile = 14i32;
pub const eAVEncH265VProfile_MainIntra_422_12: eAVEncH265VProfile = 15i32;
pub const eAVEncH265VProfile_MainIntra_444_8: eAVEncH265VProfile = 16i32;
pub const eAVEncH265VProfile_MainIntra_444_10: eAVEncH265VProfile = 17i32;
pub const eAVEncH265VProfile_MainIntra_444_12: eAVEncH265VProfile = 18i32;
pub const eAVEncH265VProfile_MainIntra_444_16: eAVEncH265VProfile = 19i32;
pub const eAVEncH265VProfile_MainStill_420_8: eAVEncH265VProfile = 20i32;
pub const eAVEncH265VProfile_MainStill_444_8: eAVEncH265VProfile = 21i32;
pub const eAVEncH265VProfile_MainStill_444_16: eAVEncH265VProfile = 22i32;
pub type eAVEncInputVideoSystem = i32;
pub const eAVEncInputVideoSystem_Unspecified: eAVEncInputVideoSystem = 0i32;
pub const eAVEncInputVideoSystem_PAL: eAVEncInputVideoSystem = 1i32;
pub const eAVEncInputVideoSystem_NTSC: eAVEncInputVideoSystem = 2i32;
pub const eAVEncInputVideoSystem_SECAM: eAVEncInputVideoSystem = 3i32;
pub const eAVEncInputVideoSystem_MAC: eAVEncInputVideoSystem = 4i32;
pub const eAVEncInputVideoSystem_HDV: eAVEncInputVideoSystem = 5i32;
pub const eAVEncInputVideoSystem_Component: eAVEncInputVideoSystem = 6i32;
pub type eAVEncMPACodingMode = i32;
pub const eAVEncMPACodingMode_Mono: eAVEncMPACodingMode = 0i32;
pub const eAVEncMPACodingMode_Stereo: eAVEncMPACodingMode = 1i32;
pub const eAVEncMPACodingMode_DualChannel: eAVEncMPACodingMode = 2i32;
pub const eAVEncMPACodingMode_JointStereo: eAVEncMPACodingMode = 3i32;
pub const eAVEncMPACodingMode_Surround: eAVEncMPACodingMode = 4i32;
pub type eAVEncMPAEmphasisType = i32;
pub const eAVEncMPAEmphasisType_None: eAVEncMPAEmphasisType = 0i32;
pub const eAVEncMPAEmphasisType_50_15: eAVEncMPAEmphasisType = 1i32;
pub const eAVEncMPAEmphasisType_Reserved: eAVEncMPAEmphasisType = 2i32;
pub const eAVEncMPAEmphasisType_CCITT_J17: eAVEncMPAEmphasisType = 3i32;
pub type eAVEncMPALayer = i32;
pub const eAVEncMPALayer_1: eAVEncMPALayer = 1i32;
pub const eAVEncMPALayer_2: eAVEncMPALayer = 2i32;
pub const eAVEncMPALayer_3: eAVEncMPALayer = 3i32;
pub type eAVEncMPVFrameFieldMode = i32;
pub const eAVEncMPVFrameFieldMode_FieldMode: eAVEncMPVFrameFieldMode = 0i32;
pub const eAVEncMPVFrameFieldMode_FrameMode: eAVEncMPVFrameFieldMode = 1i32;
pub type eAVEncMPVIntraVLCTable = i32;
pub const eAVEncMPVIntraVLCTable_Auto: eAVEncMPVIntraVLCTable = 0i32;
pub const eAVEncMPVIntraVLCTable_MPEG1: eAVEncMPVIntraVLCTable = 1i32;
pub const eAVEncMPVIntraVLCTable_Alternate: eAVEncMPVIntraVLCTable = 2i32;
pub type eAVEncMPVLevel = i32;
pub const eAVEncMPVLevel_Low: eAVEncMPVLevel = 1i32;
pub const eAVEncMPVLevel_Main: eAVEncMPVLevel = 2i32;
pub const eAVEncMPVLevel_High1440: eAVEncMPVLevel = 3i32;
pub const eAVEncMPVLevel_High: eAVEncMPVLevel = 4i32;
pub type eAVEncMPVProfile = i32;
pub const eAVEncMPVProfile_unknown: eAVEncMPVProfile = 0i32;
pub const eAVEncMPVProfile_Simple: eAVEncMPVProfile = 1i32;
pub const eAVEncMPVProfile_Main: eAVEncMPVProfile = 2i32;
pub const eAVEncMPVProfile_High: eAVEncMPVProfile = 3i32;
pub const eAVEncMPVProfile_422: eAVEncMPVProfile = 4i32;
pub type eAVEncMPVQScaleType = i32;
pub const eAVEncMPVQScaleType_Auto: eAVEncMPVQScaleType = 0i32;
pub const eAVEncMPVQScaleType_Linear: eAVEncMPVQScaleType = 1i32;
pub const eAVEncMPVQScaleType_NonLinear: eAVEncMPVQScaleType = 2i32;
pub type eAVEncMPVScanPattern = i32;
pub const eAVEncMPVScanPattern_Auto: eAVEncMPVScanPattern = 0i32;
pub const eAVEncMPVScanPattern_ZigZagScan: eAVEncMPVScanPattern = 1i32;
pub const eAVEncMPVScanPattern_AlternateScan: eAVEncMPVScanPattern = 2i32;
pub type eAVEncMPVSceneDetection = i32;
pub const eAVEncMPVSceneDetection_None: eAVEncMPVSceneDetection = 0i32;
pub const eAVEncMPVSceneDetection_InsertIPicture: eAVEncMPVSceneDetection = 1i32;
pub const eAVEncMPVSceneDetection_StartNewGOP: eAVEncMPVSceneDetection = 2i32;
pub const eAVEncMPVSceneDetection_StartNewLocatableGOP: eAVEncMPVSceneDetection = 3i32;
pub type eAVEncMuxOutput = i32;
pub const eAVEncMuxOutputAuto: eAVEncMuxOutput = 0i32;
pub const eAVEncMuxOutputPS: eAVEncMuxOutput = 1i32;
pub const eAVEncMuxOutputTS: eAVEncMuxOutput = 2i32;
pub type eAVEncVP9VProfile = i32;
pub const eAVEncVP9VProfile_unknown: eAVEncVP9VProfile = 0i32;
pub const eAVEncVP9VProfile_420_8: eAVEncVP9VProfile = 1i32;
pub const eAVEncVP9VProfile_420_10: eAVEncVP9VProfile = 2i32;
pub const eAVEncVP9VProfile_420_12: eAVEncVP9VProfile = 3i32;
pub type eAVEncVideoChromaResolution = i32;
pub const eAVEncVideoChromaResolution_SameAsSource: eAVEncVideoChromaResolution = 0i32;
pub const eAVEncVideoChromaResolution_444: eAVEncVideoChromaResolution = 1i32;
pub const eAVEncVideoChromaResolution_422: eAVEncVideoChromaResolution = 2i32;
pub const eAVEncVideoChromaResolution_420: eAVEncVideoChromaResolution = 3i32;
pub const eAVEncVideoChromaResolution_411: eAVEncVideoChromaResolution = 4i32;
pub type eAVEncVideoChromaSubsampling = i32;
pub const eAVEncVideoChromaSubsamplingFormat_SameAsSource: eAVEncVideoChromaSubsampling = 0i32;
pub const eAVEncVideoChromaSubsamplingFormat_ProgressiveChroma: eAVEncVideoChromaSubsampling = 8i32;
pub const eAVEncVideoChromaSubsamplingFormat_Horizontally_Cosited: eAVEncVideoChromaSubsampling = 4i32;
pub const eAVEncVideoChromaSubsamplingFormat_Vertically_Cosited: eAVEncVideoChromaSubsampling = 2i32;
pub const eAVEncVideoChromaSubsamplingFormat_Vertically_AlignedChromaPlanes: eAVEncVideoChromaSubsampling = 1i32;
pub type eAVEncVideoColorLighting = i32;
pub const eAVEncVideoColorLighting_SameAsSource: eAVEncVideoColorLighting = 0i32;
pub const eAVEncVideoColorLighting_Unknown: eAVEncVideoColorLighting = 1i32;
pub const eAVEncVideoColorLighting_Bright: eAVEncVideoColorLighting = 2i32;
pub const eAVEncVideoColorLighting_Office: eAVEncVideoColorLighting = 3i32;
pub const eAVEncVideoColorLighting_Dim: eAVEncVideoColorLighting = 4i32;
pub const eAVEncVideoColorLighting_Dark: eAVEncVideoColorLighting = 5i32;
pub type eAVEncVideoColorNominalRange = i32;
pub const eAVEncVideoColorNominalRange_SameAsSource: eAVEncVideoColorNominalRange = 0i32;
pub const eAVEncVideoColorNominalRange_0_255: eAVEncVideoColorNominalRange = 1i32;
pub const eAVEncVideoColorNominalRange_16_235: eAVEncVideoColorNominalRange = 2i32;
pub const eAVEncVideoColorNominalRange_48_208: eAVEncVideoColorNominalRange = 3i32;
pub type eAVEncVideoColorPrimaries = i32;
pub const eAVEncVideoColorPrimaries_SameAsSource: eAVEncVideoColorPrimaries = 0i32;
pub const eAVEncVideoColorPrimaries_Reserved: eAVEncVideoColorPrimaries = 1i32;
pub const eAVEncVideoColorPrimaries_BT709: eAVEncVideoColorPrimaries = 2i32;
pub const eAVEncVideoColorPrimaries_BT470_2_SysM: eAVEncVideoColorPrimaries = 3i32;
pub const eAVEncVideoColorPrimaries_BT470_2_SysBG: eAVEncVideoColorPrimaries = 4i32;
pub const eAVEncVideoColorPrimaries_SMPTE170M: eAVEncVideoColorPrimaries = 5i32;
pub const eAVEncVideoColorPrimaries_SMPTE240M: eAVEncVideoColorPrimaries = 6i32;
pub const eAVEncVideoColorPrimaries_EBU3231: eAVEncVideoColorPrimaries = 7i32;
pub const eAVEncVideoColorPrimaries_SMPTE_C: eAVEncVideoColorPrimaries = 8i32;
pub type eAVEncVideoColorTransferFunction = i32;
pub const eAVEncVideoColorTransferFunction_SameAsSource: eAVEncVideoColorTransferFunction = 0i32;
pub const eAVEncVideoColorTransferFunction_10: eAVEncVideoColorTransferFunction = 1i32;
pub const eAVEncVideoColorTransferFunction_18: eAVEncVideoColorTransferFunction = 2i32;
pub const eAVEncVideoColorTransferFunction_20: eAVEncVideoColorTransferFunction = 3i32;
pub const eAVEncVideoColorTransferFunction_22: eAVEncVideoColorTransferFunction = 4i32;
pub const eAVEncVideoColorTransferFunction_22_709: eAVEncVideoColorTransferFunction = 5i32;
pub const eAVEncVideoColorTransferFunction_22_240M: eAVEncVideoColorTransferFunction = 6i32;
pub const eAVEncVideoColorTransferFunction_22_8bit_sRGB: eAVEncVideoColorTransferFunction = 7i32;
pub const eAVEncVideoColorTransferFunction_28: eAVEncVideoColorTransferFunction = 8i32;
pub type eAVEncVideoColorTransferMatrix = i32;
pub const eAVEncVideoColorTransferMatrix_SameAsSource: eAVEncVideoColorTransferMatrix = 0i32;
pub const eAVEncVideoColorTransferMatrix_BT709: eAVEncVideoColorTransferMatrix = 1i32;
pub const eAVEncVideoColorTransferMatrix_BT601: eAVEncVideoColorTransferMatrix = 2i32;
pub const eAVEncVideoColorTransferMatrix_SMPTE240M: eAVEncVideoColorTransferMatrix = 3i32;
pub type eAVEncVideoContentType = i32;
pub const eAVEncVideoContentType_Unknown: eAVEncVideoContentType = 0i32;
pub const eAVEncVideoContentType_FixedCameraAngle: eAVEncVideoContentType = 1i32;
pub type eAVEncVideoFilmContent = i32;
pub const eAVEncVideoFilmContent_VideoOnly: eAVEncVideoFilmContent = 0i32;
pub const eAVEncVideoFilmContent_FilmOnly: eAVEncVideoFilmContent = 1i32;
pub const eAVEncVideoFilmContent_Mixed: eAVEncVideoFilmContent = 2i32;
pub type eAVEncVideoOutputFrameRateConversion = i32;
pub const eAVEncVideoOutputFrameRateConversion_Disable: eAVEncVideoOutputFrameRateConversion = 0i32;
pub const eAVEncVideoOutputFrameRateConversion_Enable: eAVEncVideoOutputFrameRateConversion = 1i32;
pub const eAVEncVideoOutputFrameRateConversion_Alias: eAVEncVideoOutputFrameRateConversion = 2i32;
pub type eAVEncVideoOutputScanType = i32;
pub const eAVEncVideoOutputScan_Progressive: eAVEncVideoOutputScanType = 0i32;
pub const eAVEncVideoOutputScan_Interlaced: eAVEncVideoOutputScanType = 1i32;
pub const eAVEncVideoOutputScan_SameAsInput: eAVEncVideoOutputScanType = 2i32;
pub const eAVEncVideoOutputScan_Automatic: eAVEncVideoOutputScanType = 3i32;
pub type eAVEncVideoSourceScanType = i32;
pub const eAVEncVideoSourceScan_Automatic: eAVEncVideoSourceScanType = 0i32;
pub const eAVEncVideoSourceScan_Interlaced: eAVEncVideoSourceScanType = 1i32;
pub const eAVEncVideoSourceScan_Progressive: eAVEncVideoSourceScanType = 2i32;
pub type eAVFastDecodeMode = i32;
pub const eVideoDecodeCompliant: eAVFastDecodeMode = 0i32;
pub const eVideoDecodeOptimalLF: eAVFastDecodeMode = 1i32;
pub const eVideoDecodeDisableLF: eAVFastDecodeMode = 2i32;
pub const eVideoDecodeFastest: eAVFastDecodeMode = 32i32;
pub type eAVScenarioInfo = i32;
pub const eAVScenarioInfo_Unknown: eAVScenarioInfo = 0i32;
pub const eAVScenarioInfo_DisplayRemoting: eAVScenarioInfo = 1i32;
pub const eAVScenarioInfo_VideoConference: eAVScenarioInfo = 2i32;
pub const eAVScenarioInfo_Archive: eAVScenarioInfo = 3i32;
pub const eAVScenarioInfo_LiveStreaming: eAVScenarioInfo = 4i32;
pub const eAVScenarioInfo_CameraRecord: eAVScenarioInfo = 5i32;
pub const eAVScenarioInfo_DisplayRemotingWithFeatureMap: eAVScenarioInfo = 6i32;
pub type eVideoEncoderDisplayContentType = i32;
pub const eVideoEncoderDisplayContent_Unknown: eVideoEncoderDisplayContentType = 0i32;
pub const eVideoEncoderDisplayContent_FullScreenVideo: eVideoEncoderDisplayContentType = 1i32;
pub const g_wszSpeechFormatCaps: &'static str = "SpeechFormatCap";
pub const g_wszWMCPAudioVBRQuality: &'static str = "_VBRQUALITY";
pub const g_wszWMCPAudioVBRSupported: &'static str = "_VBRENABLED";
pub const g_wszWMCPCodecName: &'static str = "_CODECNAME";
pub const g_wszWMCPDefaultCrisp: &'static str = "_DEFAULTCRISP";
pub const g_wszWMCPMaxPasses: &'static str = "_PASSESRECOMMENDED";
pub const g_wszWMCPSupportedVBRModes: &'static str = "_SUPPORTEDVBRMODES";
