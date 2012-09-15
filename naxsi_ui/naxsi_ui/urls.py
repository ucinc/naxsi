from django.conf.urls import patterns, include, url

from django.conf import settings

from django.contrib import admin

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$', 'nx_extract.views.index'),
    url(r'^admin/graph/$', 'nx_extract.admin_views.graph'),
    url(r'^admin/log-feeder/$', 'nx_extract.admin_views.log_feeder'),
    url(r'^admin/exc-viewer/$', 'nx_extract.admin_views.exc_viewer'),
    url(r'^admin/', include(admin.site.urls)),
)

if settings.DEBUG:
    urlpatterns += patterns('django.views.static',
    (r'^media/(?P<path>.*)$', 
        'serve', {
        'document_root': '/Volumes/HDD/Users/seb/svn/naxsi/branches/django/naxsi_ui/media/',
        'show_indexes': True }),)
