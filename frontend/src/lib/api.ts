import axios, { AxiosInstance, AxiosError } from 'axios'

const API_BASE_URL = '/api/v1'

class APIClient {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    // Request interceptor to add auth token
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('auth_token')
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
        }
        return config
      },
      (error) => Promise.reject(error)
    )

    // Response interceptor to handle errors
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (error.response?.status === 401) {
          // Token expired or invalid
          localStorage.removeItem('auth_token')
          window.location.href = '/login'
        }
        return Promise.reject(error)
      }
    )
  }

  // Setup
  async getSetupStatus() {
    const { data } = await this.client.get('/setup/status')
    return data
  }

  async performSetup(username: string, password: string) {
    const { data } = await this.client.post('/setup', { username, password })
    return data
  }

  // Auth
  async login(username: string, password: string) {
    const { data } = await this.client.post('/auth/login', { username, password })
    return data
  }

  async getCurrentUser() {
    const { data } = await this.client.get('/auth/me')
    return data
  }

  // Authorities
  async listAuthorities() {
    const { data } = await this.client.get('/authorities')
    return data
  }

  async getAuthority(id: string) {
    const { data } = await this.client.get(`/authorities/${id}`)
    return data
  }

  async createRootCA(request: any) {
    const { data } = await this.client.post('/authorities', request)
    return data
  }

  async importCA(request: any) {
    const { data } = await this.client.post('/authorities/import', request)
    return data
  }

  async deleteAuthority(id: string) {
    await this.client.delete(`/authorities/${id}`)
  }

  async exportAuthority(id: string, format: string, password?: string, legacy?: boolean, certOnly?: boolean) {
    const { data } = await this.client.post(
      `/authorities/${id}/export`,
      { format, password, legacy, cert_only: certOnly },
      { responseType: 'blob' }
    )
    return data
  }

  // Certificates
  async listCertificates() {
    const { data } = await this.client.get('/certificates')
    return data
  }

  async getCertificate(id: string) {
    const { data } = await this.client.get(`/certificates/${id}`)
    return data
  }

  async createCertificate(request: any) {
    const { data} = await this.client.post('/certificates', request)
    return data
  }

  async exportCertificate(id: string, format: string, password?: string, legacy?: boolean, splitFiles?: boolean) {
    const response = await this.client.post(
      `/certificates/${id}/export`,
      { format, password, legacy, split_files: splitFiles },
      { responseType: 'blob' }
    )
    return response
  }

  async revokeCertificate(id: string) {
    const { data } = await this.client.put(`/certificates/${id}/revoke`)
    return data
  }

  async deleteCertificate(id: string) {
    await this.client.delete(`/certificates/${id}`)
  }
}

export const apiClient = new APIClient()
export default apiClient
