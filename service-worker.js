self.addEventListener('push', event => {
 const data = event.data ? event.data.json() : {};
 event.waitUntil(
  self.registration.showNotification(data.title || 'Zox Code Suporte',{
   body:data.body || '',
   icon:data.icon || '/logo.png',
   badge:'/logo.png',
   data:{url:data.url || '/'}
  })
 );
});
self.addEventListener('notificationclick', event=>{
 event.notification.close();
 event.waitUntil(clients.openWindow(event.notification.data.url));
});
