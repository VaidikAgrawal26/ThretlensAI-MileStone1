const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
export async function api(path, options={}) {
  const token=localStorage.getItem('threatlens_token');
  const headers=new Headers(options.headers||{});
  if(token) headers.set('Authorization',`Bearer ${token}`);
  const response=await fetch(`${API_URL}${path}`,{...options,headers});
  const text=await response.text(); let data={};
  try{data=text?JSON.parse(text):{}}catch{data={detail:text}}
  if(!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}
export {API_URL};
