declare module "swc-registry" {
  export interface SWCRelationships {
    Category?: string;
    References?: string[];
  }

  export interface EntryData {
    Id: string;
    Title: string;
    Description: string;
    Remediation: string;
    Relationships?: SWCRelationships | string;
  }

  export class SWC {
    getEntryData(id: string): EntryData | undefined;
  }
}