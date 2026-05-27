export type VerificationStatus = 'pending' | 'verified' | 'failed'
export type VerificationMethod = 'dns_txt' | 'well_known_file'

export interface Domain {
  id: string
  user_id: string
  domain: string
  verification_status: VerificationStatus
  verification_method: VerificationMethod
  verification_token: string
  verified_at: string | null
  created_at: string
  updated_at: string
}

export interface DomainVerificationInstructions {
  domain: string
  token: string
  dns_txt: {
    record_name: string
    record_type: 'TXT'
    record_value: string
  }
  well_known_file: {
    url: string
    file_path: string
    content: string
  }
}

export interface CreateDomainInput {
  domain: string
}

export interface VerifyDomainInput {
  method: VerificationMethod
}
