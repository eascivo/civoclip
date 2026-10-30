export interface MediaSource { uri: string; language?: string }
export interface MediaAsset { id: string; source: MediaSource; durationSeconds: number }
export interface Segment { start: number; end: number; text: string }
export interface Transcript { language: string; segments: Segment[] }
export interface Translation { language: string; segments: Segment[] }
export interface Highlight { start: number; end: number; score: number; title: string }
export interface ExportArtifact { uri: string; format: 'mp4' | 'webm' }
export interface Ingest { ingest(source: MediaSource): Promise<MediaAsset> }
export interface Transcribe { transcribe(asset: MediaAsset): Promise<Transcript> }
export interface Translate { translate(transcript: Transcript, language: string): Promise<Translation> }
export interface HighlightDetect { detect(transcript: Transcript): Promise<Highlight[]> }
export interface ClipExport { export(asset: MediaAsset, highlight: Highlight): Promise<ExportArtifact> }
export class PipelineNotImplemented extends Error {
  constructor(stage: string) { super(`${stage} is a pipeline placeholder`); this.name = 'PipelineNotImplemented'; }
}
export const pipeline: { ingest: Ingest; transcribe: Transcribe; translate: Translate; highlightDetect: HighlightDetect; clipExport: ClipExport } = {
  ingest: { async ingest() { throw new PipelineNotImplemented('ingest'); } },
  transcribe: { async transcribe() { throw new PipelineNotImplemented('transcribe'); } },
  translate: { async translate() { throw new PipelineNotImplemented('translate'); } },
  highlightDetect: { async detect() { throw new PipelineNotImplemented('highlight-detect'); } },
  clipExport: { async export() { throw new PipelineNotImplemented('clip/export'); } },
};
