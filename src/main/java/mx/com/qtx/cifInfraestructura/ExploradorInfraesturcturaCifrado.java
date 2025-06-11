package mx.com.qtx.cifInfraestructura;

import java.security.Provider;
import java.security.Security;
import java.security.Provider.Service;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ExploradorInfraesturcturaCifrado {

	public static void main(String[] args) {
//		mostrarProveedoresSeguridad();
      mostrarServiciosSeguridadDisponibles();
//      mostrarAlgoritmosDisponiblesPara("KeyPairGenerator");
		
	}
	private static void mostrarServiciosSeguridadDisponibles() {
		Set<String> serviciosUnicos = getNombresServiciosSeguridadDisponibles();
        System.out.println("Servicios criptográficos disponibles:");
        serviciosUnicos.stream()
                        .sorted().map(s ->"   " + s)
                        .forEach(System.out::println);
	}

	private static Set<String> getNombresServiciosSeguridadDisponibles() {
		Set<String> serviciosUnicos = new HashSet<>();
	        
	        for (Provider p : Security.getProviders()) {
	            for (Service s : p.getServices()) {
	                serviciosUnicos.add(s.getType());
	            }
	        }
		return serviciosUnicos;
	}

	private static void mostrarAlgoritmosDisponiblesPara(String nombreServicio) {
		Provider[] proveedores = Security.getProviders();
        System.out.println("Algoritmos disponibles para " + nombreServicio
        		+ ":");
        for (Provider proveedor : proveedores) {
            // Obtener servicios de cada proveedor
            Set<Service> servicios = proveedor.getServices();
            for (Service servicio : servicios) {
                // Filtrar por servicios de generación de claves
                if (servicio.getType().equalsIgnoreCase(nombreServicio)) {
                    System.out.println("- " + servicio.getAlgorithm());
                }
            }
        }
	}

	private static void mostrarProveedoresSeguridad() {
		System.out.println("Proveedores:");
		List.of(Security.getProviders())
		                .forEach(p->mostrarProveedor(p));
	}

	private static void mostrarProveedor(Provider p) {
		System.out.println();
		System.out.print(p.getName() + " " );
		System.out.println(p.getVersionStr());
		System.out.println(p.getInfo());
		
		System.out.println("Servicios soportados:");
		p.getServices().stream()
		               .sorted((s1,s2)->s1.getType().compareTo(s2.getType()))
		               .forEach(s->System.out.printf("  %-30s c/algoritmo: %s\n",
		            		                            s.getType(),s.getAlgorithm() ));
		
//		mostrarPropiedadesProveedor(p);
	}

	private static void mostrarPropiedadesProveedor(Provider p) {
		p.entrySet()
		 .forEach(par->System.out.printf("%-55s:%-15s  [%s]\n", par.getKey(), 
				                                                par.getValue().toString(), 
				                                                par.getValue().getClass().getName() ));
	}

}
